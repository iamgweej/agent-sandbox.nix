# Test fixture: an allowed domain that resolves to host loopback. No local
# port is opened, so NO_PROXY stays unset and the request reaches sockd.
{
  port ? "18950",
  pkgs ? import ../../pinned-nixpkgs.nix { },
}:
let
  sandbox = import ../../../default.nix { pkgs = pkgs; };
in
sandbox.mkSandbox {
  pkg = pkgs.bashInteractive;
  binName = "bash";
  outName = "sandboxed-bash-loopback-domain";
  allowedPackages = [
    pkgs.coreutils
    pkgs.curl
  ];
  allowedEndpoints = [ "localtest.me:${port}" ];
}
