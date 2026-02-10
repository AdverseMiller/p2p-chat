#pragma once

#include "common/util.hpp"

#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>

#ifdef HAVE_UPNP
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>
#endif

namespace common {

struct UpnpMapping {
  bool ok = false;
  uint16_t external_port = 0;
  std::string control_url;
  std::string service_type;
  std::string lan_addr;
};

class UpnpManager {
 public:
  UpnpManager() = default;
  ~UpnpManager() { remove_mapping_best_effort(); }

  UpnpMapping try_map(uint16_t internal_port, std::string_view description) {
#ifdef HAVE_UPNP
    UpnpMapping out;
    int err = 0;
    UPNPDev* devlist = upnpDiscover(1500, nullptr, nullptr, 0, 0, 2, &err);
    if (!devlist) {
      log("UPnP: no devices discovered");
      return out;
    }

    UPNPUrls urls;
    IGDdatas data;
    char lanaddr[64] = {};
    char wanaddr[64] = {};
    std::memset(&urls, 0, sizeof(urls));
    std::memset(&data, 0, sizeof(data));

    const int igd =
        UPNP_GetValidIGD(devlist, &urls, &data, lanaddr, sizeof(lanaddr), wanaddr, sizeof(wanaddr));
    freeUPNPDevlist(devlist);
    if (igd == 0) {
      log("UPnP: no valid IGD found");
      FreeUPNPUrls(&urls);
      return out;
    }

    const std::string lan = lanaddr;
    const std::string control = urls.controlURL ? urls.controlURL : "";
    const std::string service = data.first.servicetype;

    if (control.empty() || service.empty() || lan.empty()) {
      log("UPnP: IGD info incomplete");
      FreeUPNPUrls(&urls);
      return out;
    }

    uint16_t mapped_ext = 0;
    const std::string desc(description);
    for (int i = 0; i < 10; ++i) {
      const uint16_t ext = static_cast<uint16_t>(internal_port + i);
      const std::string ext_s = std::to_string(ext);
      const std::string int_s = std::to_string(internal_port);
      const int rc = UPNP_AddPortMapping(control.c_str(), service.c_str(), ext_s.c_str(), int_s.c_str(),
                                         lan.c_str(), desc.c_str(), "TCP", nullptr, "0");
      if (rc == UPNPCOMMAND_SUCCESS) {
        mapped_ext = ext;
        break;
      }
    }

    if (mapped_ext == 0) {
      log("UPnP: port mapping failed");
      FreeUPNPUrls(&urls);
      return out;
    }

    out.ok = true;
    out.external_port = mapped_ext;
    out.control_url = control;
    out.service_type = service;
    out.lan_addr = lan;

    mapping_ = out;
    log("UPnP: mapped external TCP port " + std::to_string(mapped_ext) + " -> internal " +
        std::to_string(internal_port));
    FreeUPNPUrls(&urls);
    return out;
#else
    (void)internal_port;
    (void)description;
    log("UPnP unavailable; running without automatic port mapping");
    return UpnpMapping{};
#endif
  }

  void remove_mapping_best_effort() {
#ifdef HAVE_UPNP
    if (!mapping_ || !mapping_->ok) return;
    const std::string ext_s = std::to_string(mapping_->external_port);
    const int rc = UPNP_DeletePortMapping(mapping_->control_url.c_str(),
                                         mapping_->service_type.c_str(),
                                         ext_s.c_str(),
                                         "TCP",
                                         nullptr);
    if (rc == UPNPCOMMAND_SUCCESS) {
      log("UPnP: removed mapping for external TCP port " + ext_s);
    } else {
      log("UPnP: failed to remove mapping (best-effort)");
    }
    mapping_.reset();
#endif
  }

 private:
  std::optional<UpnpMapping> mapping_;
};

} // namespace common
