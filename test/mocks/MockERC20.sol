// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.20;

import {ERC20} from "openzeppelin/token/ERC20/ERC20.sol";
import {console2 as console} from "forge-std/Test.sol";

/**
 * @title ERC20Token
 * @dev This contract is an ERC20 token contract that extends the OpenZeppelin ERC20 contract.
 */
contract MockERC20 is ERC20 {
  /**
   * @dev Constructor that sets the name and symbol of the token and mints an initial supply to the contract deployer.
   */
  constructor() public ERC20("MockERC20", "MERC20") {
    _mint(msg.sender, 1000000000000000);
  }
}
