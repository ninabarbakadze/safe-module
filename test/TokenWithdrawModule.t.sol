pragma solidity ^0.8.20;

import {TokenWithdrawModule} from "../contracts/TokenWithdrawModule.sol";
import {MockSafe} from "./mocks/MockSafe.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {Test} from "forge-std/Test.sol";
import {Enum} from "safe-contracts/common/Enum.sol";
import {console2 as console} from "forge-std/Test.sol";

contract TokenWithdrawModuleTest is Test {
  bytes32 public constant DOMAIN_SEPARATOR_TYPEHASH =
    0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;

  bytes32 public constant WITHDRAW_TX_TYPEHASH = 0xe16c4fdd125cd2cb4ef4554bd0e2a6e9072c199e7c9a8a8b906a6bb32564917f;

  address deployer;
  address recipient;
  address public safeOwner;

  uint256 public safeOwnerPK;

  TokenWithdrawModule public tokenWithdrawModule;
  MockSafe public safe;
  MockERC20 public mockERC20;

  event WithdrawSuccessful(address recipient, uint256 amount);

  function setUp() public {
    deployer = actor("deployer");
    recipient = actor("recipient");

    (safeOwner, safeOwnerPK) = generateAddressAndPrivateKey("safeOwner");

    // Deploy the mock Safe contract
    vm.prank(safeOwner);
    safe = new MockSafe();

    // Deploy the MockERC20 and TokenWithdrawModule
    vm.prank(deployer);
    mockERC20 = new MockERC20();
    deployTokenWithdrawModule(address(mockERC20), address(safe));

    // Fund Safe with the given ERC20 token
    vm.prank(deployer);
    mockERC20.transfer(address(safe), 100);

    // Fund Safe with Eth
    vm.deal(address(safe), 200);
  }

  /* ---------- Helpers ---------- */

  function getExpectedDataHash(
    uint256 chainId,
    address _withdrawModule,
    address _safe,
    address _token,
    address _recipient,
    uint256 amount,
    uint256 nonce
  ) public returns (bytes32 expectedDataHash) {
    bytes32 domainSeparator = keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, chainId, _withdrawModule));
    bytes32 transferHash = keccak256(abi.encode(WITHDRAW_TX_TYPEHASH, _safe, _token, _recipient, amount, nonce));

    expectedDataHash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator, transferHash));
  }

  function generateWithdrawSignature(
    address _recipient,
    uint256 amount,
    uint256 nonce,
    uint256 pk
  ) public returns (bytes memory signature) {
    bytes32 dataHash = tokenWithdrawModule.generateWithdrawHash(_recipient, amount, nonce);

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, dataHash);
    signature = abi.encodePacked(r, s, v);
  }

  function deployTokenWithdrawModule(address _token, address _safe) public {
    tokenWithdrawModule = new TokenWithdrawModule(_token, payable(_safe));

    vm.prank(safeOwner);
    safe.enableModule(address(tokenWithdrawModule));
  }

  function actor(string memory name) public returns (address) {
    (address addr, ) = generateAddressAndPrivateKey(name);
    vm.label(addr, name);
    return addr;
  }

  function generateAddressAndPrivateKey(string memory name) public returns (address addr, uint256 pk) {
    pk = uint256(keccak256(bytes(name)));
    addr = vm.addr(pk);
  }
}

contract TokenWithdrawModuleTest_constructor is TokenWithdrawModuleTest {
  function test_deployWhenSafeAddressIsZero_shouldRevert() public {
    vm.expectRevert("Safe address must not be a zero address");
    tokenWithdrawModule = new TokenWithdrawModule(address(mockERC20), payable(address(0)));
  }

  function test_deployment_shouldSetSafe() public {
    assertEq(address(safe), address(tokenWithdrawModule.safe()));
  }

  function test_deployment_shouldSetToken() public {
    assertEq(address(mockERC20), tokenWithdrawModule.token());
  }
}

contract TokenWithdrawModuleTest_generateWithdrawDataHash is TokenWithdrawModuleTest {
  function test_chainId_shouldReturnChainId() public {
    vm.chainId(1234);
    assertEq(1234, tokenWithdrawModule.getChainId());
  }

  function test_generateWithdrawHash_returnsValidDataHash() public {
    bytes32 dataHash = tokenWithdrawModule.generateWithdrawHash(recipient, 2, tokenWithdrawModule.nonce());

    bytes32 expectedDataHash = getExpectedDataHash(
      tokenWithdrawModule.getChainId(),
      address(tokenWithdrawModule),
      address(safe),
      address(mockERC20),
      recipient,
      2,
      tokenWithdrawModule.nonce()
    );

    assertEq(dataHash, expectedDataHash);
  }

  function test_generateWithdrawHash_repeatedCalls_producesSameResults() public {
    address recipient2 = actor("recipient2");
    bytes32 dataHash = tokenWithdrawModule.generateWithdrawHash(recipient2, 3, tokenWithdrawModule.nonce());

    bytes32 duplicatedDataHash = tokenWithdrawModule.generateWithdrawHash(recipient2, 3, tokenWithdrawModule.nonce());

    bytes32 expectedDataHash = getExpectedDataHash(
      tokenWithdrawModule.getChainId(),
      address(tokenWithdrawModule),
      address(safe),
      address(mockERC20),
      recipient2,
      3,
      tokenWithdrawModule.nonce()
    );
    assertEq(dataHash, expectedDataHash);
    assertEq(duplicatedDataHash, expectedDataHash);
  }
}

contract TokenWithdrawModuleTest_withdraw is TokenWithdrawModuleTest {
  function test_withdraw_whenAmountIsZero_shouldRevert() public {
    vm.expectRevert("Amount must be greater than 0");
    tokenWithdrawModule.withdraw(recipient, 0, bytes("0"));
  }

  function test_withdraw_whenAddressIsZero_shouldRevert() public {
    vm.expectRevert("Invalid recipient address");
    tokenWithdrawModule.withdraw(address(0), 1, bytes("0"));
  }

  function test_withdraw_withUnauthorizedRecipient_shouldRevert() public {
    bytes memory signature = generateWithdrawSignature(recipient, 2, tokenWithdrawModule.nonce(), safeOwnerPK);
    vm.expectRevert("Signature could not be verified");
    tokenWithdrawModule.withdraw(actor("nonRecipient"), 2, signature);
  }

  function test_withdraw_withUnauthorizedAmount_shouldRevert() public {
    bytes memory signature = generateWithdrawSignature(recipient, 2, tokenWithdrawModule.nonce(), safeOwnerPK);
    vm.expectRevert("Signature could not be verified");
    tokenWithdrawModule.withdraw(recipient, 1, signature);
  }

  function test_withdraw_whenSignatureIsZero_shouldRevert() public {
    vm.expectRevert("Invalid signature length");
    tokenWithdrawModule.withdraw(actor("recipient"), 2, bytes("0"));
  }

  function test_withdraw_whenSignatureIsOutOfBounds_shouldRevert() public {
    vm.expectRevert("Invalid signature length");
    tokenWithdrawModule.withdraw(actor("recipient"), 2, new bytes(66));
  }

  function test_withdraw_whenSignerIsNotSafeOwner_shouldRevert() public {
    (, uint256 notSafeOwnerPk) = generateAddressAndPrivateKey("notSafeOwner");

    bytes memory signature = generateWithdrawSignature(recipient, 2, tokenWithdrawModule.nonce(), notSafeOwnerPk);

    vm.expectRevert("Signature could not be verified");
    tokenWithdrawModule.withdraw(actor("recipient"), 2, signature);
  }

  function test_withdraw_whenSuccessful_shouldTransferAndEmit() public {
    bytes memory signature = generateWithdrawSignature(recipient, 2, tokenWithdrawModule.nonce(), safeOwnerPK);

    vm.expectEmit(true, true, true, true);
    emit WithdrawSuccessful(recipient, 2);
    tokenWithdrawModule.withdraw(recipient, 2, signature);
  }

  function test_withdraw_whenSuccessful_shouldIncreaseNonce() public {
    uint256 nonceBeforeTransaction = tokenWithdrawModule.nonce();
    bytes memory signature = generateWithdrawSignature(recipient, 2, tokenWithdrawModule.nonce(), safeOwnerPK);

    tokenWithdrawModule.withdraw(recipient, 2, signature);

    uint256 nonceAfterTransaction = tokenWithdrawModule.nonce();

    assertEq(nonceAfterTransaction, nonceBeforeTransaction + 1);
  }

  function test_withdraw_whenSuccessful_shouldCallExecTransactionFromModule() public {
    bytes memory signature = generateWithdrawSignature(recipient, 2, tokenWithdrawModule.nonce(), safeOwnerPK);

    bytes memory data = abi.encodeWithSignature("transfer(address,uint256)", actor("recipient"), 2);

    vm.expectCall(
      address(safe),
      abi.encodeWithSelector(safe.execTransactionFromModule.selector, address(mockERC20), 0, data, Enum.Operation.Call)
    );
    tokenWithdrawModule.withdraw(recipient, 2, signature);
  }

  function test_withdraw_withContractSignature_shouldRevert() public {
    // R contains the contract address
    bytes32 r = bytes32(uint256(uint160(address(tokenWithdrawModule))));
    // V being 0 indicates that it's a contract signature
    uint8 v = 0;
    // S Can be any non-zero value
    bytes32 s = bytes32("0x1");

    // Simulate a contract signature
    bytes memory signature = abi.encodePacked(r, s, v);

    vm.expectRevert("Contract signatures are not supported by this module");
    tokenWithdrawModule.withdraw(recipient, 2, signature);
  }

  function test_withdraw_withEthereumSignature_shouldWithdraw() public {
    // Deploy new TokenWithdrawModule without token --> will default to Ether transfers
    deployTokenWithdrawModule(address(0), address(safe));

    bytes32 dataHash = tokenWithdrawModule.generateWithdrawHash(recipient, 2, tokenWithdrawModule.nonce());

    bytes32 signedMessage = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", dataHash));
    uint8 v = 32;
    (, bytes32 r, bytes32 s) = vm.sign(safeOwnerPK, signedMessage);
    bytes memory signature = abi.encodePacked(r, s, v);

    vm.expectEmit(true, true, true, true);
    emit WithdrawSuccessful(recipient, 2);
    tokenWithdrawModule.withdraw(recipient, 2, signature);
  }

  function test_withdraw_whenWithdrawingEth_shouldWithdraw() public {
    // Deploy new TokenWithdrawModule without token --> will default to Ether transfers
    deployTokenWithdrawModule(address(0), address(safe));

    bytes memory signature = generateWithdrawSignature(recipient, 2, tokenWithdrawModule.nonce(), safeOwnerPK);

    vm.expectEmit(true, true, true, true);
    emit WithdrawSuccessful(recipient, 2);
    tokenWithdrawModule.withdraw(recipient, 2, signature);
  }
}
