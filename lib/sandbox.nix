# mkSandbox. Everything about the sandbox itself lives in launcher/.
{ pkgs, shared }:
{
  pkg,
  binName,
  outName,
  allowedPackages,
  allowNix ? false,
  allowUnixSockets ? false,
  rwDirs ? [ ],
  rwFiles ? [ ],
  roDirs ? [ ],
  roFiles ? [ ],
  env ? { },
  allowedEndpoints ? [ "*" ],
  publishedPorts ? [ ],
  # Legacy args: accepted so assertNoLegacyArgs can name them in its error.
  restrictNetwork ? null,
  extraEnv ? null,
  stateDirs ? null,
  stateFiles ? null,
  allowedLocalPorts ? null,
  allowedDomains ? null,
  allowedHostPorts ? null,
}:
let
  platform = if pkgs.stdenv.isDarwin then "darwin" else "linux";

  implicitPackages = shared.mkImplicitPackages allowNix;

  pathStr = pkgs.lib.makeBinPath (allowedPackages ++ implicitPackages);

  pkgConfigPathStr = shared.mkPkgConfigPathStr (allowedPackages ++ implicitPackages);

  validatedAllowedEndpoints = shared.validateAllowedEndpoints allowedEndpoints;

  openNetwork = shared.isOpenNetwork validatedAllowedEndpoints;

  closurePathsFile = pkgs.writeClosure (
    allowedPackages
    ++ implicitPackages
    ++ shared.devOutputs (allowedPackages ++ implicitPackages)
    ++ [ pkg ]
    # coreutils supplies the /usr/bin/env symlink target, and is deliberately
    # not in implicitPackages so it does not leak into PATH.
    ++ (if platform == "linux" then [ pkgs.coreutils ] else [ ])
    ++ [ shared.preEntryScript ]
    # Privoxy runs inside the sandbox in restricted mode; the closure, not
    # PATH, so the agent does not see it as a tool.
    ++ (if openNetwork then [ ] else [ pkgs.privoxy ])
  );

  validatedPublishedPorts = shared.validatePublishedPorts publishedPorts;

  validatedAllowUnixSockets = shared.validateAllowUnixSockets {
    allowNix = allowNix;
    allowUnixSockets = allowUnixSockets;
  };

  sandboxBuildSpec = import ./spec.nix
    {
      pkgs = pkgs;
      shared = shared;
    }
    {
      platform = platform;
      outName = outName;
      pkg = pkg;
      binName = binName;
      sandboxPath = pathStr;
      pkgConfigPath = pkgConfigPathStr;
      allowNix = allowNix;
      rwDirs = rwDirs;
      rwFiles = rwFiles;
      roDirs = roDirs;
      roFiles = roFiles;
      env = env;
      allowedEndpoints = validatedAllowedEndpoints;
      publishedPorts = validatedPublishedPorts;
      allowUnixSockets = validatedAllowUnixSockets;
      closurePathsFile = closurePathsFile;
      preEntryScript = shared.preEntryScript;
    };

  envFragment = shared.mkEnvFragment {
    outName = outName;
    env = env;
  };

  stub = shared.mkStub {
    spec = sandboxBuildSpec;
    envFragment = envFragment;
  };

in
shared.mkWrapper {
  outName = outName;
  stub = stub;
  buildSpec = sandboxBuildSpec;
  legacyArgs = {
    restrictNetwork = restrictNetwork;
    extraEnv = extraEnv;
    stateDirs = stateDirs;
    stateFiles = stateFiles;
    allowedLocalPorts = allowedLocalPorts;
    allowedDomains = allowedDomains;
    allowedHostPorts = allowedHostPorts;
  };
  allowedEndpoints = validatedAllowedEndpoints;
  publishedPorts = validatedPublishedPorts;
  allowUnixSockets = validatedAllowUnixSockets;
}
