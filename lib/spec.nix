# Emits the JSON the launcher reads at startup. Keys are snake_case so the
# Python side needs no per-field name mapping.
{ pkgs, shared }:
{
  platform,
  outName,
  pkg,
  binName,
  sandboxPath,
  pkgConfigPath,
  allowNix,
  allowUnixSockets,
  rwDirs,
  rwFiles,
  roDirs,
  roFiles,
  env,
  allowedEndpoints,
  publishedPorts,
  closurePathsFile,
  preEntryScript,
}:
let
  emptyFile = pkgs.writeText "sandbox-empty" "";

  hostsFile = pkgs.writeText "sandbox-hosts" ''
    127.0.0.1 localhost
    ::1       localhost
  '';

  # The launcher reads the host's nix config with this, before the sandbox
  # exists. Null without allowNix, so a wrapper that never reaches a daemon
  # does not carry nix in its closure.
  nixBinary = if allowNix then "${pkgs.nix}/bin/nix" else null;

  dependencies =
    if platform == "linux" then
      {
        git = "${pkgs.git}/bin/git";
        bwrap = "${pkgs.bubblewrap}/bin/bwrap";
        pasta = "${pkgs.passt}/bin/pasta";
        nft = "${pkgs.nftables}/bin/nft";
        env = "${pkgs.coreutils}/bin/env";
        python = "${pkgs.python3}/bin/python3";
        nix = nixBinary;
      }
    else
      {
        git = "${pkgs.git}/bin/git";
        nix = nixBinary;
      };

  # Null in open mode, so an unrestricted wrapper carries neither proxy in
  # its closure. sockd runs on the host; Privoxy runs inside the sandbox.
  proxy =
    if shared.isOpenNetwork allowedEndpoints then
      null
    else
      {
        sockd = "${pkgs.dante}/bin/sockd";
        privoxy = "${pkgs.privoxy}/bin/privoxy";
        dante_rules_file = "${shared.mkDanteRules allowedEndpoints}";
      };

  platformFields =
    if platform == "linux" then
      {
        hosts_file = "${hostsFile}";
        empty_file = "${emptyFile}";
      }
    else
      { };

  spec = {
    # Read here rather than passed in, like the cacert paths below: it is a
    # constant of this source tree, not something a caller chooses. It is the
    # last release the tree descends from, so a wrapper built from an
    # unreleased or modified checkout reports that release rather than what it
    # actually contains.
    version = pkgs.lib.fileContents ../version.txt;
    platform = platform;
    out_name = outName;
    sandbox_path = sandboxPath;
    pkg_config_path = pkgConfigPath;
    allow_nix = allowNix;
    allow_unix_sockets = allowUnixSockets;
    rw_dirs = rwDirs;
    rw_files = rwFiles;
    ro_dirs = roDirs;
    ro_files = roFiles;
    # Keys only. The values are runtime shell expressions, emitted as a
    # fragment the stub sources; they never reach Python.
    env_keys = builtins.attrNames env;
    # For launch.log only; what is enforced is local_ports and the proxy.
    allowed_endpoints = map (
      e:
      if e.kind == "open" then
        "*"
      else if e.portFrom == null then
        "${e.host}:*"
      else if e.portFrom == e.portTo then
        "${e.host}:${toString e.portFrom}"
      else
        "${e.host}:${toString e.portFrom}-${toString e.portTo}"
    ) allowedEndpoints;
    # null means every host-local TCP port; [ ] means none.
    local_ports = shared.mkLocalPorts allowedEndpoints;
    published_ports = map (entry: {
      port = entry.port;
      bind_addr = entry.bindAddr;
    }) publishedPorts;
    closure_paths_file = "${closurePathsFile}";
    cacert_dir = "${pkgs.cacert}/etc/ssl/certs";
    cacert_bundle = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
    shell = "${shared.bashWrapper}/bin/bash";
    pre_entry_script = "${preEntryScript}";
    sandboxed_binary = "${pkg}/bin/${binName}";
    proxy = proxy;
    dependencies = dependencies;
  }
  // platformFields;
in
pkgs.writeText "${outName}-spec.json" (builtins.toJSON spec)
