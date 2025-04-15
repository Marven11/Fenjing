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
      python38Packages = pkgs_old.python38Packages;
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
          pip install -r requirements-devel.lock
        '';
        postShellHook = ''
          # allow pip to install wheels
          unset SOURCE_DATE_EPOCH
        '';
      };

      devShells.python38 = pkgs_old.mkShell {
        name = "python-venv";
        venvDir = "/tmp/venv-fenjing-python3.8";
        buildInputs = [
          python38Packages.python
          python38Packages.venvShellHook
        ];
        postVenvCreation = ''
          unset SOURCE_DATE_EPOCH
          # pip install -r requirements-devel.txt
        '';
        postShellHook = ''
          # allow pip to install wheels
          unset SOURCE_DATE_EPOCH
        '';
      };
      packages.default = with pkgs.python3Packages; buildPythonPackage rec {
        pname = "fenjing";
        # it takes minutes
        doCheck = false;

        nativeBuildInputs = [ pkgs.installShellFiles ];

        build-system = [
          setuptools
          setuptools-scm
        ];

        dependencies = [
          requests
          beautifulsoup4
          click
          flask
          jinja2
          prompt-toolkit
          pygments
          pysocks
          rich
        ];

        postInstall = ''
          installShellCompletion --cmd fenjing \
            --bash <(_FENJING_COMPLETE=bash_source $out/bin/fenjing) \
            --fish <(_FENJING_COMPLETE=fish_source $out/bin/fenjing) \
            --zsh <(_FENJING_COMPLETE=zsh_source $out/bin/fenjing) \
        '';

        src = ./.;
        version = (lib.strings.removeSuffix "\n" (builtins.readFile "${src}/VERSION"));
      };
    });
}
