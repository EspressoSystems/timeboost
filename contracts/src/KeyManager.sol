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
        uint64 id;
        uint64 effectiveTimestamp;
        CommitteeMember[] members;
        uint64 prevCommitteeId;
        uint64 nextCommitteeId;
    }

    event ScheduledCommittee(uint64 indexed id, uint64 effectiveTimestamp, uint64 membersCount, bytes32 membersHash, address indexed scheduledBy);
    event SetThresholdEncryptionKey(bytes thresholdEncryptionKey, address indexed setBy);
    event ChangedManager(address indexed oldManager, address indexed newManager, address indexed changedBy);

    error NotManager(address caller);
    error InvalidAddress();
    error ThresholdEncryptionKeyAlreadySet();
    error CommitteeIdDoesNotExist(uint64 committeeId, uint64 committeesLength);
    error EmptyCommittee();
    error InvalidEffectiveTimestamp(uint64 effectiveTimestamp, uint64 lastEffectiveTimestamp);
    error NoCommitteeScheduled(uint64 lastEffectiveTimestamp);
    error CommitteeIdOverflow();
    error NoCommitteees();
    error CannotRemoveRecentCommittees();
    error CannotRemoveHeadCommittee();

    bytes public thresholdEncryptionKey;
    mapping(uint64 => Committee) public committees;
    uint64 public headCommitteeId;
    uint64 private _nextCommitteeId;
    address public manager;
    uint256[48] private __gap;

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

    /**
     * @notice This function is used to initialize the contract.
     * @dev Reverts if the manager is the zero address.
     * @dev Assumes that the manager is valid.
     * @dev This must be called once when the contract is first deployed.
     * @param initialManager The initial manager.
     */
    function initialize(address initialManager) external initializer {
        if (initialManager == address(0)) {
            revert InvalidAddress();
        }
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();
        manager = initialManager;
    }

    /**
     * @notice This function is used to authorize the upgrade of the contract.
     * @dev Reverts if the caller is not the owner.
     * @dev Assumes that the new implementation is valid.
     * @param newImplementation The new implementation.
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    /**
     * @notice This function is used to set the manager.
     * @dev Reverts if the manager is the zero address or the same as the current manager.
     * @dev Reverts if the caller is not the owner.
     * @dev Assumes that the manager is valid.
     * @param newManager The new manager.
     */
    function setManager(address newManager) external virtual onlyOwner {
        if (newManager == address(0) || newManager == manager) {
            revert InvalidAddress();
        }
        address oldManager = manager;
        manager = newManager;
        emit ChangedManager(oldManager, newManager, msg.sender);
    }

    /**
     * @notice This function is used to set the threshold encryption key.
     * @dev Reverts if the threshold encryption key is already set.
     * @dev Reverts if the caller is not the manager.
     * @dev Assumes that the threshold encryption key is valid.
     * @param newThresholdEncryptionKey The threshold encryption key.
     */
    function setThresholdEncryptionKey(bytes calldata newThresholdEncryptionKey) external virtual onlyManager {
        if (thresholdEncryptionKey.length > 0) {
            revert ThresholdEncryptionKeyAlreadySet();
        }
        thresholdEncryptionKey = newThresholdEncryptionKey;
        emit SetThresholdEncryptionKey(thresholdEncryptionKey, msg.sender);
    }

    /**
     * @notice This function is used to set the next committee.
     * @dev Reverts if the members array is empty.
     * @dev Reverts if the effective timestamp is less than the last effective timestamp.
     * @dev Reverts if the committees array is at uint64.max.
     * @dev Assumes that committee members are not deleted from the committee array.
     * @dev Assumes that the committee members are valid.
     * @param effectiveTimestamp The effective timestamp of the committee.
     * @param members The committee members.
     * @return committeeId The id of the new committee.
     */
    function setNextCommittee(uint64 effectiveTimestamp, CommitteeMember[] calldata members)
        external
        virtual
        onlyManager
        returns (uint64 committeeId)
    {
        if (members.length == 0) {
            revert EmptyCommittee();
        }

        // ensure the effective timestamp is greater than the last effective timestamp
        if (_nextCommitteeId > 0) {
            uint64 lastTimestamp = committees[_nextCommitteeId - 1].effectiveTimestamp;
            if (effectiveTimestamp <= lastTimestamp) {
                revert InvalidEffectiveTimestamp(effectiveTimestamp, lastTimestamp);
            }
        }

        if (_nextCommitteeId == type(uint64).max) revert CommitteeIdOverflow();

        uint64 prevCommitteeId = _nextCommitteeId == 0 ? 0 : _nextCommitteeId - 1;
        committees[_nextCommitteeId] = Committee({
            id: _nextCommitteeId,
            effectiveTimestamp: effectiveTimestamp,
            members: members,
            prevCommitteeId: prevCommitteeId,
            nextCommitteeId: 0
        });

        // Update previous committee's nextCommitteeId
        if (_nextCommitteeId > 0) {
            committees[_nextCommitteeId - 1].nextCommitteeId = _nextCommitteeId;
        }

        _nextCommitteeId++;

        emit ScheduledCommittee(_nextCommitteeId-1, effectiveTimestamp, uint64(members.length), keccak256(abi.encode(members)), msg.sender);
        return committeeId;
    }

    /**
     * @notice This function is used to get the committee by id.
     * @dev Reverts if the id is greater than the length of the committees array.
     * @dev Reverts if the committees array is empty.
     * @dev Assumes that committees are not deleted from the committee array.
     * @param id The id of the committee.
     * @return committee The committee.
     */
    function getCommitteeById(uint64 id)
        external
        virtual
        view
        returns (Committee memory committee)
    {
        if (_nextCommitteeId == 0) {
            revert NoCommitteees();
        }
        
        if (committees[id].id != id || id < headCommitteeId) {
            revert CommitteeIdDoesNotExist(id, _nextCommitteeId);
        }
        
        return committees[id];
    }

    /**
     * @notice This function is used to get the current committee id.
     * @dev Reverts if the committees array is empty.
     * @dev Reverts if there is no committee scheduled.
     * @dev Assumes that committees are stored in ascending order of effective timestamp.
     * @dev Assumes that committees are not deleted from the committee array.
     * @return committeeId The current committee id.
     */
    function currentCommitteeId() public virtual view returns (uint64 committeeId) {
        if (_nextCommitteeId == 0) {
            revert NoCommitteees();
        }

        uint64 currentTimestamp = uint64(block.timestamp);
        if (currentTimestamp < committees[headCommitteeId].effectiveTimestamp) {
            revert NoCommitteeScheduled(committees[headCommitteeId].effectiveTimestamp);
        }

        // search backwards for the current committee id
        uint64 currCommitteeId = _nextCommitteeId - 1;
        while (currCommitteeId >= headCommitteeId) {
            if (currentTimestamp >= committees[currCommitteeId].effectiveTimestamp) {
                return currCommitteeId;
            }
            currCommitteeId = committees[currCommitteeId].prevCommitteeId;
        }
    }

    /**
     * @notice This function is used to remove a committee by id.
     * @dev Reverts if the committee ID does not exist.
     * @dev Reverts if the committee ID is 0 (first committee) or the head committee.
     * @dev Reverts if the committee became effective within the last 10 minutes.
     * @dev Updates the list pointers to maintain chain integrity.
     * @param id The id of the committee to remove.
     */
    function removeCommittee(uint64 id) external virtual onlyManager {
        if (id >= _nextCommitteeId || id < headCommitteeId) {
            revert CommitteeIdDoesNotExist(id, _nextCommitteeId);
        }

        // Can't remove committees with a timestamp in the last 10 minutes
        if(committees[id].effectiveTimestamp >= block.timestamp - 10 minutes){
            revert CannotRemoveRecentCommittees();
        }
        
        uint64 prevId = committees[id].prevCommitteeId;
        uint64 nextId = committees[id].nextCommitteeId;
        
        committees[prevId].nextCommitteeId = nextId;
        committees[nextId].prevCommitteeId = prevId;
        
        if (id == headCommitteeId) {
            headCommitteeId = nextId;
        }
        
        delete committees[id];
    }

    /**
     * @notice This function is used to get the next committee id.
     * @dev It returns the next committee id that will be scheduled even if there is no next committee.
     * @dev Assumes that committees are stored in ascending order of effective timestamp.
     * @return committeeId The next committee id.
     */
    function nextCommitteeId() public virtual view returns (uint64 committeeId) {
       return _nextCommitteeId;
    }
}
