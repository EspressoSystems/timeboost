// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract KeyManager is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    struct CommitteeMember {
        bytes pubKey;
        bytes secureChannelKey;
        bytes dkgEncKey;
        string networkAddress;
    }

    struct Committee {
        uint64 effectiveTimestamp;
        uint64 id;
        CommitteeMember[] members;
    }

    event ScheduledCommittee(uint64 indexed id, Committee committee);
    event CreatedEncryptionKeyset(uint64 indexed id, bytes thresholdEncKey);
    event ChangedManager(address indexed manager);

    error NotOwnerOrManager();
    error InvalidAddress();

    bytes public thresholdEncKey;
    uint64 public nextKeysetId;
    uint64 public nextCommitteeId;
    mapping(uint64 => Committee) public committees;
    address public manager;

    modifier onlyOwnerOrManager() {
        if (msg.sender != owner() && msg.sender != manager) {
            revert NotOwnerOrManager();
        }
        _;
    }

    constructor() {
        _disableInitializers();
    }

    function initialize(address _manager) external initializer {
        if (_manager == address(0)) {
            revert InvalidAddress();
        }
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();
        manager = _manager;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    function createEncryptionKeyset(bytes memory _thresholdEncKey) external onlyOwnerOrManager returns (uint64 keysetId) {
        uint64 thisKeysetId = nextKeysetId;
        thresholdEncKey = _thresholdEncKey;
        emit CreatedEncryptionKeyset(nextKeysetId, _thresholdEncKey);
        nextKeysetId++;
        return thisKeysetId;
    }

    function scheduleCommittee(uint64 _effectiveTimestamp, CommitteeMember[] calldata _members)
        external
        onlyOwnerOrManager
        returns (uint64)
    {
        uint64 thisCommitteeId = nextCommitteeId;
        Committee memory newCommittee =
            Committee({effectiveTimestamp: _effectiveTimestamp, id: nextCommitteeId, members: _members});
        emit ScheduledCommittee(nextCommitteeId, newCommittee);
        nextCommitteeId++;
        return thisCommitteeId;
    }

    function setManager(address _manager) external onlyOwner {
        if (_manager == address(0)) {
            revert InvalidAddress();
        }
        manager = _manager;
        emit ChangedManager(_manager);
    }
}
