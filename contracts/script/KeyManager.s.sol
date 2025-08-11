// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {KeyManager} from "../src/KeyManager.sol";

contract KeyManagerScript is Script {
    KeyManager public keyManager;

    function setUp() public {
        keyManager = new KeyManager();
    }

    function run() public {
        vm.startBroadcast();

        keyManager = new KeyManager();

        vm.stopBroadcast();
    }
}
