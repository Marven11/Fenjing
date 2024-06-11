{
  description = "Python venv development template";

  inputs = {
    utils.url = "github:numtide/flake-utils";
    nixpkgs_old.url = "https://github.com/NixOS/nixpkgs/archive/b4e193a23a1c5d8794794e65cabf1f1135d07fd9.tar.gz";
  };

  outputs = {
    self,
    nixpkgs,
    nixpkgs_old,
    utils,
    ...
  }:
    utils.lib.eachDefaultSystem (system: let
      pkgs = import nixpkgs {inherit system;};
      pkgs_old = import nixpkgs_old {inherit system;};
      pythonPackages = pkgs.python3Packages;
      python37Packages = pkgs_old.python37Packages;
    in {
      devShells.default = pkgs.mkShell {
        name = "python-venv";
        venvDir = "./.venv-nixos";
        buildInputs = [
          pythonPackages.python
          pythonPackages.venvShellHook
          pythonPackages.notebook
          pythonPackages.ipython
        ];
        postVenvCreation = ''
          unset SOURCE_DATE_EPOCH
          pip install -r requirements-devel.txt
        '';
        postShellHook = ''
          # allow pip to install wheels
          unset SOURCE_DATE_EPOCH
        '';
      };
      # python3.7 is supported because some people are still using it.
      devShells.python37 = pkgs_old.mkShell {
        name = "python-venv";
        venvDir = "./.venv";
        buildInputs = [
          python37Packages.python
          python37Packages.venvShellHook
        ];
        postVenvCreation = ''
          unset SOURCE_DATE_EPOCH
          pip install -r requirements-devel-python37.lock
        '';
        postShellHook = ''
          # allow pip to install wheels
          unset SOURCE_DATE_EPOCH
        '';
      };
    });
}
