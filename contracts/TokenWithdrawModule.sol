// SPDX-License-Identifier: Unlicensed
pragma solidity >=0.7.0 <0.9.0;

import {SignatureDecoder} from "safe-contracts/common/SignatureDecoder.sol";
import {Enum} from "safe-contracts/common/Enum.sol";
import {Safe} from "safe-contracts/Safe.sol";

/**
 * @title WithdrawModule - A Safe Module with alternative access functionality
 *        allowing accounts that are not related to the Safe,
 *        to withdraw a predetermined amount of a specific token.
 * @author Nina Barbakadze - @ninabarbakadze
 */
contract TokenWithdrawModule is SignatureDecoder {
  string public constant NAME = "Withdraw Module";
  string public constant VERSION = "0.1.0";

  // keccak256(
  //     "EIP712Domain(uint256 chainId,address verifyingContract)"
  // );
  bytes32 public constant DOMAIN_SEPARATOR_TYPEHASH =
    0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;

  // keccak256(
  //     "WithdrawTx(address safe,address token,address recipient,uint256 amount,uin256 nonce)"
  // );
  bytes32 private constant WITHDRAW_TX_TYPEHASH = 0xe16c4fdd125cd2cb4ef4554bd0e2a6e9072c199e7c9a8a8b906a6bb32564917f;

  address public immutable token;
  uint256 public nonce;
  Safe public immutable safe;

  event WithdrawSuccessful(address recipient, uint256 amount);

  /**
   * @param _token The address of an abitrary ERC-20 token managed by this module.
   * @param _safe The address of the Safe associated with this module.
   */
  constructor(address _token, address payable _safe) {
    require(_safe != address(0), "Safe address must not be a zero address");
    token = _token;
    safe = Safe(_safe);
  }

  /**
   * @notice Returns the ID of the chain the contract is currently deployed on.
   * @return The ID of the current chain as a uint256.
   */
  function getChainId() public view returns (uint256) {
    uint256 id;
    // solhint-disable-next-line no-inline-assembly
    assembly {
      id := chainid()
    }
    return id;
  }

  /**
   * @notice Encodes the withdraw transaction data that later gets hashed (see generateWithdrawHash).
   * @param recipient The address of the recipient.
   * @param amount The amount of tokens to transfer.
   * @param _nonce Unique transaction nonce.
   * @return Withdraw transaction hash bytes.
   */
  function encodeWithdrawData(address recipient, uint256 amount, uint256 _nonce) private view returns (bytes memory) {
    uint256 chainId = getChainId();
    bytes32 domainSeparator = keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, chainId, this));
    bytes32 transferHash = keccak256(abi.encode(WITHDRAW_TX_TYPEHASH, address(safe), token, recipient, amount, _nonce));
    return abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator, transferHash);
  }

  /**
   * @notice Generates a withdraw transaction hash based on the provided arguments.
   * @param recipient The address of the token recipient.
   * @param amount The amount of tokens to transfer.
   * @param _nonce Unique transaction nonce.
   * @return The computed withdraw transaction hash.
   */
  function generateWithdrawHash(address recipient, uint256 amount, uint256 _nonce) public view returns (bytes32) {
    return keccak256(encodeWithdrawData(recipient, amount, _nonce));
  }

  /**
   * @notice Verifies the validity of a provided signature for a given hash and ensures that
   *         it was signed by the owner of the Safe associated to this Module.
   * @dev Compatible with ECDSA signatures only.
   * @param dataHash The hash of the data.
   * @param signature The signature to be verified.
   * @return Boolean indicating whether the signature was signed by the Safe owner.
   */
  function verifySignature(bytes32 dataHash, bytes memory signature) internal view returns (bool) {
    require(signature.length == 65, "Invalid signature length");

    (uint8 v, bytes32 r, bytes32 s) = signatureSplit(signature, 0);
    address signer;

    require(v != 0, "Contract signatures are not supported by this module");

    if (v > 30) {
      // To support eth_sign adjust v and hash the dataHash with the Ethereum message prefix
      signer = ecrecover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", dataHash)), v - 4, r, s);
    } else {
      // Use ecrecover with the message hash for EOA signatures
      signer = ecrecover(dataHash, v, r, s);
    }

    require(signer != address(0), "Invalid signer");
    return safe.isOwner(signer);
  }

  /**
   * @notice Allows the withdrawal of ERC20 tokens or Ether from the Safe to a specified recipient.
   * @param recipient The address of the token recipient.
   * @param amount The amount of tokens to transfer.
   * @param signature The signature authorizing the withdrawal.
   */
  function withdraw(address recipient, uint256 amount, bytes memory signature) external {
    require(recipient != address(0), "Invalid recipient address");
    require(amount > 0, "Amount must be greater than 0");

    // Recreate the data hash for signature verification
    bytes32 dataHash = generateWithdrawHash(recipient, amount, nonce);

    // Check that the provided signature is valid
    require(verifySignature(dataHash, signature), "Signature could not be verified");

    // Increase nonce and execute transaction
    nonce++;

    if (token == address(0)) {
      // Execute Ether transfer and verify that it was successful
      require(safe.execTransactionFromModule(recipient, amount, "", Enum.Operation.Call), "Ether transfer failed");
    } else {
      bytes memory data = abi.encodeWithSignature("transfer(address,uint256)", recipient, amount);
      // Execute ERC20 token transfer and verify that it was successful
      require(safe.execTransactionFromModule(token, 0, data, Enum.Operation.Call), "Token transfer failed");
    }
    emit WithdrawSuccessful(recipient, amount);
  }
}
