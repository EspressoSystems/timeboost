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
        CommitteeMember[] committeeMembers;
    }

    event ScheduledCommittee(uint64 indexed id, uint64 effectiveTimestamp, uint256 membersCount, bytes32 membersHash);
    event SetThresholdEncryptionKey(bytes thresholdEncKey);
    event ChangedManager(address indexed manager);

    error NotManager(address _sender);
    error InvalidAddress(address _address);
    error ThresholdEncryptionKeyAlreadySet();
    error CommitteeIdDoesNotExist(uint64 _committeeId, uint64 _committeesLength);
    error InvalidCommitteeMembers();
    error InvalidEffectiveTimestamp(uint64 _effectiveTimestamp, uint64 _lastEffectiveTimestamp);
    error NoCommitteeScheduled(uint64 _currentTimestamp, uint64 _lastEffectiveTimestamp);
    error CommitteeIdOverflow();

    bytes public thresholdEncryptionKey;
    Committee[] public committees;
    address public manager;

    modifier onlyManager() {
        _onlyManager();
        _;
    }

    function _onlyManager() internal view {
        if (msg.sender != manager) {
            revert NotManager(msg.sender);
        }
    }

    constructor() {
        _disableInitializers();
    }

    function initialize(address _manager) external initializer {
        if (_manager == address(0)) {
            revert InvalidAddress(_manager);
        }
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();
        manager = _manager;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    function setThresholdEncryptionKey(bytes calldata _thresholdEncKey) external onlyManager {
        if (thresholdEncryptionKey.length > 0) {
            revert ThresholdEncryptionKeyAlreadySet();
        }
        thresholdEncryptionKey = _thresholdEncKey;
        emit SetThresholdEncryptionKey(_thresholdEncKey);
    }

    function setNextCommittee(uint64 _effectiveTimestamp, CommitteeMember[] calldata _members)
        external
        onlyManager
        returns (uint64 committeeId)
    {
        if (_members.length == 0) {
            revert InvalidCommitteeMembers();
        }

        // ensure the effective timestamp is greater than the last effective timestamp
        if (committees.length > 0) {
            uint64 lastTimestamp = committees[committees.length - 1].effectiveTimestamp;
            if (_effectiveTimestamp <= lastTimestamp) {
                revert InvalidEffectiveTimestamp(_effectiveTimestamp, lastTimestamp);
            }
        }

        if (committees.length > type(uint64).max) revert CommitteeIdOverflow();

        committeeId = uint64(committees.length);
        Committee storage newCommittee = committees.push();
        newCommittee.effectiveTimestamp = _effectiveTimestamp;
        newCommittee.id = committeeId;
        newCommittee.committeeMembers = _members;

        emit ScheduledCommittee(committeeId, _effectiveTimestamp, _members.length, keccak256(abi.encode(_members)));
        return committeeId;
    }

    function setManager(address _manager) external onlyOwner {
        if (_manager == address(0)) {
            revert InvalidAddress(_manager);
        }
        manager = _manager;
        emit ChangedManager(_manager);
    }

    function getCommitteeById(uint64 id)
        external
        view
        returns (uint64 effectiveTimestamp, CommitteeMember[] memory committeeMembers)
    {
        if (id >= committees.length) {
            revert CommitteeIdDoesNotExist(id, uint64(committees.length));
        }
        return (committees[id].effectiveTimestamp, committees[id].committeeMembers);
    }

    function currentCommitteeId() external view returns (uint64 committeeId) {
        if (committees.length == 0) {
            revert CommitteeIdDoesNotExist(0, 0);
        }

        uint64 currentTimestamp = uint64(block.timestamp);
        if (currentTimestamp < committees[0].effectiveTimestamp) {
            revert NoCommitteeScheduled(currentTimestamp, committees[0].effectiveTimestamp);
        }
        if (currentTimestamp >= committees[committees.length - 1].effectiveTimestamp) {
            return committees[committees.length - 1].id;
        }

        uint256 lo = 0;
        uint256 hi = committees.length - 1;
        while (lo < hi) {
            uint256 mid = (lo + hi + 1) / 2;
            if (committees[mid].effectiveTimestamp <= currentTimestamp) {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        return committees[lo].id;
    }
}
