#ifndef __ASSET_GUARD__
#define __ASSET_GUARD__

#include <stdexcept>
#include <map>
#include <string>
#include <cstdint>
#include "fty_proto.h"
#include "fty_common_mlm_utils.h"

/*
 * \brief Class that provides C++ interface for assets
 * Serialization and deserialization from all objects should be handled elsewhere due to dependencies
 */
class BasicAsset {
    public:
        /// List of valid asset statuses
        enum Status {
            Active, Nonactive
        };
        /// List of valid asset types
        enum Type {
            Type_Cluster, Type_Datacenter, Type_Device, Type_Group, Type_Hypervisor, Type_Rack, Type_Room, Type_Row,
            Type_Storage, Type_VApp, Type_VirtuService, Type_VM
        };
        /// List of valid asset subtypes
        enum Subtype {
            Subtype_Appliance, Subtype_Chassis,
            Subtype_CitrixPool, Subtype_CitrixTask, Subtype_CitrixVApp, Subtype_CitrixVM, Subtype_CitrixXenserver,
            Subtype_EPDU, Subtype_Feed, Subtype_Genset, Subtype_GPO,
            Subtype_HPITManager, Subtype_HPITManagerService, Subtype_HPITRack, Subtype_HPITServer,
            Subtype_IPMInfraServer, Subtype_IPMInfraService,
            Subtype_MicrosoftCluster, Subtype_MicrosoftHyperV, Subtype_MicrosoftServer, Subtype_MicrosoftTask,
            Subtype_MicrosoftVirtualizationMachine, Subtype_MicrosoftVM, Subtype_MicrosoftWindowsServer,
            Subtype_NetAppCluster, Subtype_NetAppNode, Subtype_NetAppOntapNode, Subtype_NetAppOntapSystem,
            Subtype_NetAppServer,
            Subtype_NutanixCluster, Subtype_NutanixNode, Subtype_NutanixPrismGateway, Subtype_NutanixVirtualizationMachine,
            Subtype_N_A, Subtype_Other, Subtype_PatchPanel, Subtype_PDU, Subtype_RackController, Subtype_Router,
            Subtype_Sensor, Subtype_SensorGPIO, Subtype_Server, Subtype_Storage, Subtype_STS, Subtype_Switch, Subtype_UPS,
            Subtype_VM,
            Subtype_VMWareCluster, Subtype_VMWareESXI, Subtype_VMWareStandaloneESXI, Subtype_VMWareTask, Subtype_VMWareVApp,
            Subtype_VMWareVCenter, Subtype_VMWareVM
        };
    protected:
        /// internal identification string (iname)
        std::string id_;
        Status status_;
        std::pair<Type, Subtype> type_subtype_;
    private:
        /// asset types string reprezentation
        std::string typeToString (Type type) const;
        /// asset types from string reprezentation
        Type stringToType (std::string type) const;
        /// asset subtypes string reprezentation
        std::string subtypeToString (Subtype subtype) const;
        /// asset subtypes from string reprezentation
        Subtype stringToSubtype (std::string subtype) const;
        /// asset statuses string reprezentation
        std::string statusToString (Status status) const;
        /// asset statuses from string reprezentation
        Status stringToStatus (std::string status) const;
    public:
        // ctors, dtors, =
        BasicAsset (std::string id, std::string status, std::string type, std::string subtype) :
                id_(id), status_(stringToStatus (status)),
                type_subtype_(std::make_pair (stringToType (type), stringToSubtype (subtype))) { };
        BasicAsset (fty_proto_t *msg)
        {
            if (fty_proto_id (msg) != FTY_PROTO_ASSET)
                throw std::invalid_argument ("Wrong fty-proto type");
            id_ = fty_proto_name (msg);
            std::string status_str = fty_proto_aux_string (msg, "status", "active");
            status_ = stringToStatus (status_str);
            std::string type_str = fty_proto_aux_string (msg, "type", "");
            std::string subtype_str = fty_proto_aux_string (msg, "subtype", "");
            type_subtype_ = std::make_pair (stringToType (type_str), stringToSubtype (subtype_str));
        }
        BasicAsset () = delete;
        BasicAsset (const BasicAsset & asset) = default;
        BasicAsset (BasicAsset && asset) = default;
        BasicAsset & operator= (const BasicAsset & asset) = default;
        BasicAsset & operator= (BasicAsset && asset) = default;
        virtual ~BasicAsset () = default;
        // handling
        /// simplified equality check
        bool operator== (const BasicAsset &asset) const { return asset.id_ == id_; };
        /// comparator for full equality check
        bool compare (const BasicAsset &asset) const;
        // getters/setters
        std::string getId () const { return id_; };
        Status getStatus () const { return status_; };
        std::string getStatusString () const { return statusToString (status_); };
        Type getType () const { return type_subtype_.first; };
        std::string getTypeString () const { return typeToString (type_subtype_.first); };
        Subtype getSubtype () const { return type_subtype_.second; };
        std::string getSubtypeString () const { return subtypeToString (type_subtype_.second); };
        void setStatus (const std::string status) { status_ = stringToStatus (status); };
        void setType (const std::string type) { type_subtype_.first = stringToType (type); };
        void setSubtype (const std::string subtype) { type_subtype_.second = stringToSubtype (subtype); };
};

/// extends basic asset with location and user identification and priority
class ExtendedAsset : public BasicAsset {
    protected:
        /// external name (ename) provided by user
        std::string name_;
        /// direct parent iname
        std::string parent_id_;
        /// priority 1..5 (1 is most, 5 is least)
        uint8_t priority_;
    public:
        // ctors, dtors, =
        ExtendedAsset (std::string id, std::string status, std::string type, std::string subtype, std::string name,
                std::string parent_id, int priority) : BasicAsset (id, status, type, subtype), name_(name),
                parent_id_(parent_id), priority_(priority) { };
        ExtendedAsset (std::string id, std::string status, std::string type, std::string subtype, std::string name,
                std::string parent_id, std::string priority) : BasicAsset (id, status, type, subtype), name_(name),
                parent_id_(parent_id) {
                setPriority (priority);
            };
        ExtendedAsset (fty_proto_t *msg): BasicAsset (msg)
        {
            name_ = fty_proto_ext_string (msg, "name", fty_proto_name (msg));
            parent_id_ = fty_proto_aux_string (msg, "parent_name.1", "");
            priority_ = fty_proto_aux_number (msg, "priority", 5);
        }
        ExtendedAsset () = delete;
        ExtendedAsset (const ExtendedAsset & asset) = default;
        ExtendedAsset (ExtendedAsset && asset) = default;
        ExtendedAsset & operator= (const ExtendedAsset & asset) = default;
        ExtendedAsset & operator= (ExtendedAsset && asset) = default;
        virtual ~ExtendedAsset () = default;
        // handling
        bool compare (const ExtendedAsset &asset) const;
        // getters/setters
        std::string getName () const { return name_; };
        std::string getParentId () const { return parent_id_; };
        std::string getPriorityString () const { return std::string ("P") + std::to_string (priority_); };
        int getPriority () const { return priority_; };
        void setName (const std::string name) { name_ = name; };
        void setParentId (const std::string parent_id) { parent_id_ = parent_id; };
        void setPriority (int priority) { priority_ = priority; };
        void setPriority (const std::string priority);
};

/// provide full details about the asset without specifying asset type
class FullAsset : public ExtendedAsset {
    public:
        typedef std::map<std::string, std::string> HashMap;
    protected:
        /// aux map storage (parents, etc)
        HashMap aux_;
        /// ext map storage (asset-specific values)
        HashMap ext_;
    public:
        // ctors, dtors, =
        FullAsset (std::string id, std::string status, std::string type, std::string subtype, std::string name,
                std::string parent_id, int priority, HashMap aux, HashMap ext) :
                ExtendedAsset (id, status, type, subtype, name, parent_id, priority), aux_(aux), ext_(ext) { };
        FullAsset (std::string id, std::string status, std::string type, std::string subtype, std::string name,
                std::string parent_id, std::string priority, HashMap aux, HashMap ext) :
                ExtendedAsset (id, status, type, subtype, name, parent_id, priority), aux_(aux), ext_(ext) { };
        FullAsset (fty_proto_t *msg): ExtendedAsset (msg)
        {
            zhash_t *aux = fty_proto_aux (msg);
            zhash_t *ext = fty_proto_ext (msg);
            aux_ = MlmUtils::zhash_to_map (aux);
            ext_ = MlmUtils::zhash_to_map (ext);
        }
        FullAsset () = delete;
        FullAsset (const FullAsset & asset) = default;
        FullAsset (FullAsset && asset) = default;
        FullAsset & operator= (const FullAsset & asset) = default;
        FullAsset & operator= (FullAsset && asset) = default;
        virtual ~FullAsset () = default;
        // handling
        bool compare (const FullAsset &asset) const;
        // getters/setters
        HashMap getAux () const { return aux_; };
        HashMap getExt () const { return ext_; };
        void setAux (HashMap aux) { aux_ = aux; };
        void setExt (HashMap ext) { ext_ = ext; };
        std::string getAuxItem (const std::string &key) const;
        std::string getExtItem (const std::string &key) const;
        /// get item from either aux or ext
        std::string getItem (const std::string &key) const;
        void setAuxItem (const std::string &key, const std::string &value) { aux_[key] = value; };
        void setExtItem (const std::string &key, const std::string &value) { ext_[key] = value; };
};

#endif // __ASSET_GUARD__
