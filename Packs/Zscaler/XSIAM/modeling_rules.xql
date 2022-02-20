[MODEL: dataset="zscaler_firewall_log", model="Network", version=0.7]
| alter XDM.Network.event_timestamp = to_timestamp(rt, "MILLIS")
      XDM.Network.outcome = if(act=="Allow", "SUCCESS", "UNKNOWN")
      XDM.Network.reason = reason
      XDM.Network.network_protocol = if(proto==17, "UDP", proto==6, "UDP", proto==1, "ICMP", "UNKNOWN")
      XDM.Network.application_protocol_category = cs5
      XDM.Network.application_protocol = cs3
      XDM.Network.protocol_layers = arrayconcat(proto, cs2, cs3)
      XDM.Network.duration = floor(coalesce(cn1, avgduration) / 1000)
      XDM.Network.is_completed = true
      XDM.Network.threats = arrayconcat(struct)
      XDM.Network.Observer.vendor = cefDeviceVendor
      XDM.Network.Observer.product = cefDeviceProduct
      XDM.Network.Observer.version = cefDeviceVersion
      XDM.Network.Observer.action = if(act=="Allow", "ALLOW", "UNKNOWN")
      XDM.Network.Source.host.ipv4_addresses = arrayconcat(src)
      XDM.Network.Source.user.username = suser
      XDM.Network.Source.ipv4 = src
      XDM.Network.Source.port = spt
      XDM.Network.Source.bytes = out
      XDM.Network.Destination.host.ipv4_addresses = arrayconcat(dst)
      XDM.Network.Destination.location.country = destCountry
      XDM.Network.Destination.ipv4 = dst
      XDM.Network.Destination.port = dpt
      XDM.Network.Destination.bytes = in



[MODEL: dataset="zscaler_web_log", model="Network", version=0.7]
| alter XDM.Network.event_timestamp = to_timestamp(rt, "MILLIS")
      XDM.Network.outcome = if(act=="Allowed", "SUCCESS", "UNKNOWN")
      XDM.Network.reason = reason
      XDM.Network.network_protocol = "UNKNOWN"
      XDM.Network.application_protocol_category = cs3
      XDM.Network.application_protocol = app
      XDM.Network.protocol_layers = arrayconcat(app)
      XDM.Network.is_completed = true
      XDM.Network.threats = arrayconcat(struct)
      XDM.Network.Observer.vendor = cefDeviceVendor
      XDM.Network.Observer.product = cefDeviceProduct
      XDM.Network.Observer.version = cefDeviceVersion
      XDM.Network.Observer.action = if(act=="Allow", "ALLOW", "UNKNOWN")
      XDM.Network.Source.host.ipv4_addresses = arrayconcat(src)
      XDM.Network.Source.user.username = suser
      XDM.Network.Source.ipv4 = src
      XDM.Network.Source.port = spt
      XDM.Network.Source.bytes = out
      XDM.Network.Destination.host.ipv4_addresses = arrayconcat(dst)
      XDM.Network.Destination.ipv4 = dst
      XDM.Network.Destination.port = dpt
      XDM.Network.Destination.bytes = in
      XDM.Network.Main.http.referrer=requestContext
      XDM.Network.Main.http.url=request
      XDM.Network.Main.http.url_category=cat
      XDM.Network.Main.http.domain=dhost
      XDM.Network.Main.http.user_agent=requestClientApplication
      XDM.Network.Main.http.content_type=contenttype
      XDM.Network.Main.http.browse=uaclass
      XDM.Network.Main.http.method=requestMethod
      XDM.Network.Main.http.response_code=reason
