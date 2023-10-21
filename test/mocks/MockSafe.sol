// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.20;

import {Enum} from "safe-contracts/common/Enum.sol";

contract MockSafe {
  address owner;

  mapping(address => address) modules;

  constructor() {
    owner = msg.sender;
  }

  function isOwner(address _owner) public view returns (bool) {
    return owner == _owner;
  }

  function execTransactionFromModule(
    address to,
    uint256 value,
    bytes memory data,
    Enum.Operation operation
  ) public virtual returns (bool success) {
    // Only whitelisted modules are allowed.
    require(modules[msg.sender] != address(0), "Module is not enabled");

    uint256 txGas = type(uint256).max;
    assembly {
      success := call(txGas, to, value, add(data, 0x20), mload(data), 0, 0)
    }
    return success;
  }

  function enableModule(address module) public {
    require(isOwner(msg.sender), "Caller must be the owner");

    // Module address cannot be null or sentinel.
    require(module != address(0));
    // Module cannot be added twice.
    require(modules[module] == address(0));
    modules[module] = module;
  }
}
