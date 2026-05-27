{ lib
, stdenv
, fetchFromGitHub
, cmake
, pkg-config
, capstone
}:

stdenv.mkDerivation (finalAttrs: {
  pname = "roe";
  version = "1.0.0";

  src = fetchFromGitHub {
    owner = "USER";
    repo = "roe";
    rev = "v${finalAttrs.version}";
    # Hash is filled in at release time.
    hash = "sha256-0000000000000000000000000000000000000000000=";
  };

  nativeBuildInputs = [ cmake pkg-config ];
  buildInputs = [ capstone ];

  cmakeFlags = [
    "-DROE_BUILD_TESTS=OFF"
  ];

  meta = with lib; {
    description = "A disassembler fit for humans";
    homepage = "https://github.com/USER/roe";
    license = licenses.asl20;
    mainProgram = "roe";
    platforms = platforms.unix;
  };
})
