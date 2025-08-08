// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {KeyManager} from "../src/KeyManager.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract KeyManagerTest is Test {
    KeyManager public keyManagerProxy;
    address public manager;
    address public owner;

    function setUp() public {
        owner = makeAddr("owner");
        manager = makeAddr("manager");
        KeyManager keyManagerImpl = new KeyManager();
        bytes memory data = abi.encodeWithSelector(KeyManager.initialize.selector, manager);
        vm.prank(owner);
        ERC1967Proxy proxy = new ERC1967Proxy(address(keyManagerImpl), data);
        keyManagerProxy = KeyManager(address(proxy));
    }

    function test_createEncryptionKeyset() public {
        vm.prank(manager);
        vm.expectEmit(true, true, true, true);
        emit KeyManager.CreatedEncryptionKeyset(0, bytes32(0));
        keyManagerProxy.createEncryptionKeyset(bytes32(0));
        assertEq(keyManagerProxy.thresholdEncKey(), bytes32(0));
        assertEq(keyManagerProxy.nextKeysetId(), 1);
    }

    function test_scheduleCommittee() public {
        KeyManager.CommitteeMember[] memory committeeMembers = new KeyManager.CommitteeMember[](1);

        bytes32 randomBytes = bytes32(uint256(1));
        committeeMembers[0] = KeyManager.CommitteeMember({
            pubKey: randomBytes,
            secureChannelKey: randomBytes,
            dkgEncKey: abi.encodePacked(randomBytes),
            networkAddress: "0x0000000000000000000000000000000000000000"
        });

        KeyManager.Committee memory committee = KeyManager.Committee({
            effectiveTimestamp: uint64(block.timestamp),
            id: keyManagerProxy.nextCommitteeId(),
            members: committeeMembers
        });

        vm.prank(manager);
        vm.expectEmit(true, true, true, true);
        emit KeyManager.ScheduledCommittee(0, committee);
        keyManagerProxy.scheduleCommittee(uint64(block.timestamp), committeeMembers);

        assertEq(keyManagerProxy.nextCommitteeId(), 1);
    }

    function test_setManager() public {
        vm.prank(owner);
        vm.expectEmit(true, true, true, true);
        emit KeyManager.ChangedManager(manager);
        keyManagerProxy.setManager(manager);
        assertEq(keyManagerProxy.manager(), manager);
    }

    function test_revertWhenNotOwnerOrManager_createEncryptionKeyset() public {
        vm.expectRevert(abi.encodeWithSelector(KeyManager.NotOwnerOrManager.selector));
        keyManagerProxy.createEncryptionKeyset(bytes32(0));
    }

    function test_revertWhenNotManager_scheduleCommittee() public {
        vm.expectRevert(abi.encodeWithSelector(KeyManager.NotOwnerOrManager.selector));
        keyManagerProxy.scheduleCommittee(uint64(block.timestamp), new KeyManager.CommitteeMember[](0));
    }

    function test_revertWhenNotOwner_setManager() public {
        vm.prank(manager);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, manager));
        keyManagerProxy.setManager(manager);
    }

    function test_revertWhenInvalidAddress_setManager() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(KeyManager.InvalidAddress.selector));
        keyManagerProxy.setManager(address(0));
    }
}
