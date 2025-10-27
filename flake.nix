{
  description = "Python venv development template";

  inputs = {
    nixpkgs_old.url = "https://github.com/NixOS/nixpkgs/archive/b4e193a23a1c5d8794794e65cabf1f1135d07fd9.tar.gz";
  };

  outputs =
    {
      self,
      nixpkgs,
      nixpkgs_old,
      ...
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      # 为每个系统创建pkgs
      forEachSystem = nixpkgs.lib.genAttrs systems;

      # 旧版nixpkgs可能不支持所有系统，需要处理
      getPkgsOld =
        system:
        if nixpkgs_old.legacyPackages ? ${system} then
          nixpkgs_old.legacyPackages.${system}
        else
          import nixpkgs_old { inherit system; };

    in
    {
      devShells = forEachSystem (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          pkgs_old = getPkgsOld system;
          pythonPackages = pkgs.python3Packages;

          python38Packages = pkgs_old.python38Packages;

        in
        {
          default = pkgs.mkShell {
            name = "python-venv";
            venvDir = "./.venv-nixos";
            buildInputs = with pythonPackages; [
              python
              venvShellHook
              notebook
              ipython
              requests
              beautifulsoup4
              click
              flask
              jinja2
              prompt_toolkit
              pygments
              pysocks
              build
              black
              rich
            ];
            postVenvCreation = ''
              unset SOURCE_DATE_EPOCH
              # pip install -r requirements-devel.lock
            '';
            postShellHook = ''
              unset SOURCE_DATE_EPOCH
            '';
          };

          python38 = pkgs_old.mkShell {
            name = "python38-venv";
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
              unset SOURCE_DATE_EPOCH
            '';
          };
        }
      );

      packages = forEachSystem (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          pythonPackages = pkgs.python3Packages;
        in
        {
          default =
            with pythonPackages;
            buildPythonPackage rec {
              pname = "fenjing";
              doCheck = false;
              pyproject = true;

              nativeBuildInputs = [
                pkgs.installShellFiles
                setuptools
                setuptools-scm
              ];

              propagatedBuildInputs = [
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
                  --zsh <(_FENJING_COMPLETE=zsh_source $out/bin/fenjing)
              '';

              src = ./.;
              version = builtins.readFile "${src}/VERSION";
            };
        }
      );
    };
}
