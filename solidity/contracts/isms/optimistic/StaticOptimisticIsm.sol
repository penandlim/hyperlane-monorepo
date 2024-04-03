// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0;
import {AbstractOptimisticIsm} from "./AbstractOptimisticIsm.sol";
import {MetaProxy} from "../../libs/MetaProxy.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {IInterchainSecurityModule} from "../../interfaces/IInterchainSecurityModule.sol";
import {Message} from "../../libs/Message.sol";

abstract contract AbstractMetaProxyOptimisticIsm is AbstractOptimisticIsm {
    /**
     * @inheritdoc AbstractOptimisticIsm
     */
    function watchersAndThreshold(bytes calldata)
        public
        view
        virtual
        override
        returns (address[] memory, uint8)
    {
        return abi.decode(MetaProxy.metadata(), (address[], uint8));
    }
}

contract StaticOptimisticIsm is
    AbstractMetaProxyOptimisticIsm,
    OwnableUpgradeable
{
    // ============ Public Storage ============
    uint96 public constant MAX_FRAUD_WINDOW = 30 days;
    uint96 public constant MIN_FRAUD_WINDOW = 1 days;

    // The address of the static Interchain Security Module
    address public staticModule;

    // The length of the static fraud window
    uint96 public staticFraudWindow;

    // mapping of addresses to whether they are a watcher
    mapping(address => bool) private _isWatcher;

    // ============ Events ============
    event SubmoduleSet(address ism);
    event FraudWindowSet(uint256 fraudWindow);
    event MarkedFraudulent(address indexed ism, address indexed watcher);

    // ============ Initializer ============

    /**
     * @notice Initializes the contract with a specified owner and ISM module.
     * @param _owner The address of the owner of this contract.
     * @param _module The address of the Interchain Security Module to be used.
     * @param _fraudWindowDuration The length of the fraud window in seconds.
     */
    function initialize(
        address _owner,
        address _module,
        uint256 _fraudWindowDuration
    ) public initializer {
        __Ownable_init();
        transferOwnership(_owner);
        _setSubmodule(_module);
        _setFraudWindowDuration(_fraudWindowDuration);

        // Set up access control
        (address[] memory watchers, ) = this.watchersAndThreshold("");
        for (uint256 i = 0; i < watchers.length; i++) {
            _isWatcher[watchers[i]] = true;
        }
    }

    // ============= Modifiers =============
    modifier onlyWatcher() {
        require(isWatcher(msg.sender), "!watcher");
        _;
    }

    // ============ External Functions ============

    /**
     * @notice Sets a new static Interchain Security Module
     * @param _ism The address of the new Interchain Security Module
     */
    function setSubmodule(address _ism) external onlyOwner {
        _setSubmodule(_ism);
    }

    /**
     * @notice Marks an ISM as fraudulent
     * @dev This function can only be called by a watcher
     * @param ism The address of ISM to mark as fraudulent
     */
    function markFraudulent(address ism) external override onlyWatcher {
        require(ism != address(0), "address(0)");
        require(!fraudulent[ism][msg.sender], "already fraudulent");
        fraudulent[ism][msg.sender] = true;
        fraudulentCounter[ism]++;

        emit MarkedFraudulent(ism, msg.sender);
    }

    // ============ Public Functions ============

    /**
     * @inheritdoc AbstractOptimisticIsm
     */
    function isWatcher(bytes calldata, address _watcher)
        public
        view
        override
        returns (bool)
    {
        return isWatcher(_watcher);
    }

    /**
     * @notice Returns whether an address is a watcher for this ISM
     * @param _watcher The address to check
     * @return Whether the address is a watcher
     */
    function isWatcher(address _watcher) public view returns (bool) {
        return _isWatcher[_watcher];
    }

    /**
     * @notice Returns the currently active ISM
     * @return module The ISM to use to verify _message
     */
    function submodule(bytes calldata)
        public
        view
        override
        returns (IInterchainSecurityModule)
    {
        return IInterchainSecurityModule(staticModule);
    }

    /**
     * @notice Returns the length of the fraud window
     * @return The length of the fraud window
     */
    function fraudWindow(bytes calldata)
        public
        view
        override
        returns (uint256)
    {
        return staticFraudWindow;
    }

    // ============ Internal Functions ============
    function _setSubmodule(address ism) internal {
        require(ism != address(0), "address(0)");
        staticModule = ism;
        emit SubmoduleSet(ism);
    }

    function _setFraudWindowDuration(uint256 _fraudWindowDuration) internal {
        require(
            MIN_FRAUD_WINDOW <= _fraudWindowDuration &&
                _fraudWindowDuration <= MAX_FRAUD_WINDOW,
            "fraudOutOfBounds"
        );
        staticFraudWindow = uint96(_fraudWindowDuration);
        emit FraudWindowSet(_fraudWindowDuration);
    }
}
