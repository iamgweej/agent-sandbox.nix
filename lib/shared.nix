{ pkgs }:
let
  errorPrefix = "[ERROR][agent-sandbox.nix]";
  # Forces --norc --noprofile however bash is reached (SHELL, /bin/sh,
  # direct exec), so the sandboxed process cannot source /etc/bashrc or
  # /etc/profile.
  bashWrapper =
    pkgs.runCommand "bash-norc"
      {
        nativeBuildInputs = [ pkgs.makeBinaryWrapper ];
      }
      # bash
      ''
        mkdir -p $out/bin
        makeBinaryWrapper ${pkgs.bashInteractive}/bin/bash $out/bin/bash \
          --add-flags "--norc" \
          --add-flags "--noprofile"
        ln -s bash $out/bin/sh
      '';
  # Shared by the endpoint and published-port validators.
  validPort = port: builtins.isInt port && port >= 1 && port <= 65535;

  # Parses allowedEndpoints into
  #   { kind = "open" | "domain" | "local"; host; portFrom; portTo; }
  # "*" is open mode; "localhost:<ports>" is a host-local port or range,
  # reached directly rather than through sockd; anything else is a domain
  # (and its subdomains) that sockd matches by name. A domain with no port
  # expands to two entries, 80 and 443. portFrom and portTo are null only
  # for "localhost:*".
  validateAllowedEndpoints =
    allowedEndpoints:
    let
      hint = "Entries are \"*\", \"<domain>[:<port>[-<port>]]\" or \"localhost:<port>[-<port>]\" / \"localhost:*\"";
      fail =
        entry: reason:
        builtins.throw "${errorPrefix} allowedEndpoints: invalid entry ${builtins.toJSON entry}: ${reason}. ${hint}.";
      # Lowercase ASCII labels only: an uppercase name would still match in
      # sockd, but a non-ASCII one would need IDNA, which nothing here does.
      label = "[a-z0-9]([a-z0-9-]*[a-z0-9])?";
      isDomain = host: builtins.match "${label}(\\.${label})*" host != null;
      # A numeric last label is an IPv4 literal (or its shorthand); no TLD is
      # all digits, and sockd must only ever see names.
      isIpLike = host: builtins.match "(.*\\.)?[0-9]+" host != null;
      parsePort =
        entry: text:
        if builtins.match "[1-9][0-9]{0,4}" text == null then
          fail entry "bad port ${builtins.toJSON text}"
        else
          let
            port = builtins.fromJSON text;
          in
          if validPort port then port else fail entry "port ${text} is outside 1-65535";
      parsePorts =
        entry: text:
        let
          range = builtins.match "([^-]*)-([^-]*)" text;
        in
        if range == null then
          let
            port = parsePort entry text;
          in
          {
            portFrom = port;
            portTo = port;
          }
        else
          let
            portFrom = parsePort entry (builtins.elemAt range 0);
            portTo = parsePort entry (builtins.elemAt range 1);
          in
          if portFrom > portTo then
            fail entry "reversed port range"
          else
            {
              portFrom = portFrom;
              portTo = portTo;
            };
      parse =
        entry:
        if !(builtins.isString entry) then
          fail entry "not a string"
        else if entry == "*" then
          [
            {
              kind = "open";
              host = null;
              portFrom = null;
              portTo = null;
            }
          ]
        else
          let
            parts = builtins.match "([^:]*)(:(.*))?" entry;
            host = pkgs.lib.toLower (builtins.elemAt parts 0);
            portText = builtins.elemAt parts 2;
          in
          if host == "localhost" then
            if portText == null then
              fail entry "a localhost entry needs a port, a range, or *"
            else if portText == "*" then
              [
                {
                  kind = "local";
                  host = host;
                  portFrom = null;
                  portTo = null;
                }
              ]
            else
              [
                (
                  {
                    kind = "local";
                    host = host;
                  }
                  // parsePorts entry portText
                )
              ]
          else if !(isDomain host) then
            fail entry "not an ASCII domain name (IP literals and CIDRs are not accepted)"
          else if isIpLike host then
            fail entry "IP literals are not accepted, only domain names"
          else if portText == null then
            map
              (port: {
                kind = "domain";
                host = host;
                portFrom = port;
                portTo = port;
              })
              [
                80
                443
              ]
          else
            [
              (
                {
                  kind = "domain";
                  host = host;
                }
                // parsePorts entry portText
              )
            ];
    in
    if !(builtins.isList allowedEndpoints) then
      builtins.throw "${errorPrefix} allowedEndpoints must be a list of strings. ${hint}"
    else
      pkgs.lib.unique (builtins.concatMap parse allowedEndpoints);

  isOpenNetwork = endpoints: builtins.any (e: e.kind == "open") endpoints;

  # null means every host-local TCP port; [ ] means none.
  mkLocalPorts =
    endpoints:
    let
      local = builtins.filter (e: e.kind == "local") endpoints;
    in
    if builtins.any (e: e.portFrom == null) local then
      null
    else
      map (e: {
        from = e.portFrom;
        to = e.portTo;
      }) local;

  # The sockd rule body for the domain entries. The launcher prepends the
  # runtime header (listen port, external interface, logging, client rule).
  # One field per line: command: and log: take lists that run to the end of
  # the line. `from: 0/0` because sockd listens on 127.0.0.1 only, so every
  # client is already local. The leading dot matches the domain itself and
  # every subdomain. command: connect refuses BIND, which would let the agent
  # accept inbound connections on the host, and UDP ASSOCIATE.
  mkDanteRules =
    endpoints:
    let
      domains = builtins.filter (e: e.kind == "domain") endpoints;
      portSpec =
        e:
        if e.portFrom == e.portTo then
          "port = ${toString e.portFrom}"
        else
          "port ${toString e.portFrom} - ${toString e.portTo}";
      rule = e: ''
        socks pass {
          from: 0/0 to: .${e.host} ${portSpec e}
          command: connect
          log: connect error
        }
      '';
    in
    pkgs.writeText "sandbox-dante-rules.conf" (
      pkgs.lib.concatMapStrings rule domains
      + ''
        socks block {
          from: 0/0 to: 0/0
          log: connect error
        }
      ''
    );

  # Deliberately no null form: "every port, reachable from the host" is
  # never the intended published surface, unlike allowedHostPorts' null.
  validatePublishedPorts =
    publishedPorts:
    if !(builtins.isList publishedPorts) then
      builtins.throw "${errorPrefix} publishedPorts must be a list whose entries are integers from 1 to 65535 or { port = <int>; bindAddr = \"<ipv4>\"; }"
    else
      let
        validAddr =
          addr:
          builtins.isString addr
          && builtins.match "([0-9]{1,3}\\.){3}[0-9]{1,3}" addr != null
          && builtins.all (octet: pkgs.lib.toInt octet <= 255) (
            builtins.filter builtins.isString (builtins.split "\\." addr)
          );
        normalize =
          entry:
          if builtins.isInt entry then
            {
              port = entry;
              bindAddr = "127.0.0.1";
            }
          else if builtins.isAttrs entry then
            {
              port = entry.port or null;
              bindAddr = entry.bindAddr or "127.0.0.1";
            }
          else
            {
              port = null;
              bindAddr = null;
            };
        normalized = map normalize publishedPorts;
        invalid = builtins.filter (
          entry: !(validPort entry.port) || !(validAddr entry.bindAddr)
        ) normalized;
      in
      if invalid != [ ] then
        builtins.throw "${errorPrefix} publishedPorts entries must be integers from 1 to 65535 or { port = <1-65535>; bindAddr = \"<ipv4>\"; }. Invalid: ${builtins.toJSON invalid}"
      else
        pkgs.lib.unique normalized;
  # Raised on macOS too, where the combination would technically work, so
  # the two platforms accept the same configurations.
  validateAllowUnixSockets =
    { allowNix, allowUnixSockets }:
    if !(builtins.isBool allowUnixSockets) then
      builtins.throw "${errorPrefix} allowUnixSockets must be a boolean"
    else if allowNix && !allowUnixSockets then
      builtins.throw "${errorPrefix} allowNix = true requires allowUnixSockets = true: the nix daemon is reached over an AF_UNIX socket, which the sandbox denies by default."
    else
      allowUnixSockets;

  assertNoLegacyArgs =
    {
      restrictNetwork,
      extraEnv,
      stateDirs,
      stateFiles,
      allowedLocalPorts,
      allowedDomains,
      allowedHostPorts,
    }:
    let
      legacyArgHints = {
        allowedLocalPorts =
          if allowedLocalPorts != null then
            "- The 'allowedLocalPorts' argument is deprecated. Use 'allowedEndpoints' instead, e.g. [ \"localhost:5432\" ]."
          else
            null;
        restrictNetwork =
          if restrictNetwork != null then
            "- The 'restrictNetwork' argument is deprecated. Network access is controlled by 'allowedEndpoints': omit it for open internet, list domains to filter, or [] to block all."
          else
            null;
        allowedDomains =
          if allowedDomains != null then
            "- The 'allowedDomains' argument is replaced by 'allowedEndpoints': a list of domains (subdomains included, ports 80 and 443), e.g. [ \"anthropic.com\" \"github.com:22\" ]. HTTP method filtering is gone; null becomes [ \"*\" ]."
          else
            null;
        allowedHostPorts =
          if allowedHostPorts != null then
            "- The 'allowedHostPorts' argument is replaced by 'allowedEndpoints': write each port as \"localhost:<port>\" or \"localhost:<from>-<to>\"; null becomes \"localhost:*\"."
          else
            null;
        extraEnv =
          if extraEnv != null then "- The 'extraEnv' argument is deprecated. Use 'env' instead." else null;
        stateDirs =
          if stateDirs != null then
            "- The 'stateDirs' argument is deprecated. Use 'rwDirs' instead."
          else
            null;
        stateFiles =
          if stateFiles != null then
            "- The 'stateFiles' argument is deprecated. Use 'rwFiles' instead."
          else
            null;
      };
      throwMsgHints = builtins.concatStringsSep "\n" (
        builtins.attrValues (pkgs.lib.filterAttrs (_: v: v != null) legacyArgHints)
      );
      throwMsg = "${errorPrefix} Deprecated arguments:\n\n${throwMsgHints}";
    in
    if
      restrictNetwork != null
      || extraEnv != null
      || stateDirs != null
      || stateFiles != null
      || allowedLocalPorts != null
      || allowedDomains != null
      || allowedHostPorts != null
    then
      builtins.throw throwMsg
    else
      null;

  # sleep by store path: bash has no builtin one, and the sandbox PATH need
  # not include coreutils.
  preEntryScript = pkgs.writeShellScript "pre-entry-script" (
    builtins.replaceStrings [ "@sleep@" ] [ "${pkgs.coreutils}/bin/sleep" ] (
      builtins.readFile ./pre-entry-script.sh
    )
  );

  # __pycache__ would otherwise change the store hash from one build to the
  # next depending on whether anything had imported the package in place.
  launcherSource = builtins.filterSource (path: type: baseNameOf path != "__pycache__") ../launcher;

  launcherPackage = pkgs.runCommand "agent-sandbox-launcher" { } ''
    mkdir -p $out
    cp -r ${launcherSource} $out/launcher
  '';

  mkImplicitPackages =
    allowNix:
    [
      pkgs.cacert
      bashWrapper
    ]
    ++ (if allowNix then [ pkgs.nix ] else [ ]);

  devOutputs = packages: pkgs.lib.unique (map pkgs.lib.getDev packages);

  mkPkgConfigPathStr =
    packages:
    builtins.concatStringsSep ":" (
      builtins.concatMap (out: [
        "${out}/lib/pkgconfig"
        "${out}/share/pkgconfig"
      ]) (devOutputs packages)
    );

  # One declare_env line per declared variable. toJSON supplies the double
  # quotes the value expands inside, so a value containing spaces stays one
  # word; escapeShellArg carries the fragment through unexpanded until
  # declare_env evals it.
  mkEnvFragment =
    { outName, env }:
    pkgs.writeText "${outName}-env" (
      pkgs.lib.concatMapStrings (
        name:
        "declare_env ${pkgs.lib.escapeShellArg name} ${
          pkgs.lib.escapeShellArg (builtins.toJSON env.${name})
        }\n"
      ) (builtins.attrNames env)
    );

  mkStub =
    { spec, envFragment }:
    pkgs.replaceVars ./stub.sh {
      bash = "${pkgs.bashInteractive}/bin/bash";
      python = "${pkgs.python3}/bin/python3";
      launcher = "${launcherPackage}";
      spec = "${spec}";
      envFragment = "${envFragment}";
      errorPrefix = errorPrefix;
    };

  # The seqs force the validations at eval time; nothing else does, so
  # without them the errors would only surface when the agent is launched.
  mkWrapper =
    {
      outName,
      stub,
      buildSpec,
      legacyArgs,
      allowedEndpoints,
      publishedPorts,
      allowUnixSockets,
    }:
    builtins.seq (assertNoLegacyArgs legacyArgs) (
      builtins.deepSeq allowedEndpoints (
        builtins.seq publishedPorts (
          builtins.seq allowUnixSockets (
            pkgs.runCommand outName { } ''
              mkdir -p $out/bin
              install -m755 ${stub} $out/bin/${outName}
            ''
            // {
              buildSpec = buildSpec;
            }
          )
        )
      )
    );
in
{
  bashWrapper = bashWrapper;
  assertNoLegacyArgs = assertNoLegacyArgs;
  validateAllowedEndpoints = validateAllowedEndpoints;
  isOpenNetwork = isOpenNetwork;
  mkLocalPorts = mkLocalPorts;
  mkDanteRules = mkDanteRules;
  validatePublishedPorts = validatePublishedPorts;
  validateAllowUnixSockets = validateAllowUnixSockets;
  preEntryScript = preEntryScript;
  launcherPackage = launcherPackage;
  mkImplicitPackages = mkImplicitPackages;
  devOutputs = devOutputs;
  mkPkgConfigPathStr = mkPkgConfigPathStr;
  mkEnvFragment = mkEnvFragment;
  mkStub = mkStub;
  mkWrapper = mkWrapper;
}
