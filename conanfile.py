import os
import subprocess

from conan import ConanFile
from conan.tools.cmake import CMakeToolchain, CMake
from conan.tools.files import copy


FPTN_VERSION = os.environ.get("FPTN_VERSION") or "0.0.0"


class FPTN(ConanFile):
    name = "fptn"
    version = FPTN_VERSION
    requires = (
        "argparse/3.2",
        "boost/1.90.0",
        "brotli/1.2.0",
        "cpp-httplib/0.46.1",
        "fmt/12.1.0",
        "jwt-cpp/0.7.2",
        "nlohmann_json/3.12.0",
        "protobuf/5.29.3",
        "re2/20251105",
        "spdlog/1.17.0",
        "zlib/1.3.2",
    )
    settings = (
        "os",
        "arch",
        "compiler",
        "build_type",
    )
    generators = ("CMakeDeps",)
    options = {
        "setup": [True, False],
        "with_gui_client": [True, False],
        "build_only_fptn_lib": [True, False],
        "openwrt": [True, False],
    }
    default_options = {
        # --- program ---
        "setup": False,
        "with_gui_client": False,
        "build_only_fptn_lib": False,
        "openwrt": False,
        # -- depends --
        "*:fPIC": True,
        "*:shared": False,
        # --- protobuf options ---
        "protobuf/*:lite": True,
        "protobuf/*:upb": False,
        "protobuf/*:with_rtti": False,
        "protobuf/*:with_zlib": False,
        "protobuf/*:upb": False,
        "protobuf/*:debug_suffix": False,
        # --- boost options ---
        "boost/*:without_atomic": False,
        "boost/*:without_system": False,
        "boost/*:without_process": False,
        "boost/*:without_exception": False,
        "boost/*:without_container": False,
        "boost/*:without_filesystem": False,
        "boost/*:without_coroutine": False,
        "boost/*:without_context": False,
        "boost/*:without_timer": False,
        "boost/*:without_json": False,
        "boost/*:without_random": False,
        "boost/*:without_iostreams": False,
        "boost/*:without_chrono": False,
        "boost/*:without_regex": False,
        "boost/*:without_zlib": False,
        "boost/*:without_nowide": False,
        "boost/*:without_locale": False,
        "boost/*:without_thread": False,
        "boost/*:without_python": True,
        "boost/*:without_contract": True,
        "boost/*:without_fiber": True,
        "boost/*:without_graph": True,
        "boost/*:without_graph_parallel": True,
        "boost/*:without_log": True,
        "boost/*:without_math": True,
        "boost/*:without_mpi": True,
        "boost/*:without_program_options": True,
        "boost/*:without_serialization": True,
        "boost/*:without_stacktrace": True,
        "boost/*:without_test": True,
        "boost/*:without_url": True,
        "boost/*:without_type_erasure": True,
        "boost/*:without_wave": True,
        # --- Qt ---
        "qt/*:shared": True,
        "qt/*:openssl": False,
        "qt/*:qttools": True,
        "qt/*:with_harfbuzz": True,
        "qt/*:with_freetype": True,
        "qt/*:with_icu": True,
        "qt/*:with_mysql": False,
        "qt/*:with_pq": False,
        "qt/*:with_odbc": False,
        "qt/*:with_zstd": False,
        "qt/*:with_brotli": False,
        "qt/*:with_dbus": False,
        "qt/*:with_openal": False,
        "qt/*:with_gstreamer": False,
        "qt/*:with_pulseaudio": False,
        # --- prometheuscpp dependency ---
        "prometheus-cpp/*:with_compression": False,
        "prometheus-cpp/*:with_push": False,
        "civetweb/*:with_ssl": False,
        "civetweb/*:disable_werror": True,
        # --- freetype ---
        "freetype/*:with_brotli": False,
    }
    exports_sources = (
        "CMakeLists.txt",
        "src/*",
        "depends/*",
        "tests/*",
    )

    def requirements(self):
        self._register_local_recipe("boringssl", "openssl", "boringssl", True, False)
        self._register_local_recipe("yaff", "yaff", "0.0.0", visible=False)
        if self.options.with_gui_client:
            self.requires("qt/6.7.3")
        if self.settings.os != "Windows":
            self.requires("meson/1.10.2", override=True, force=True)
        if not self.options.build_only_fptn_lib:
            self.requires("libidn2/2.3.8")
            self.requires("prometheus-cpp/1.3.0")
        if self._use_mimalloc():
            self.requires("mimalloc/3.3.2")

    def build_requirements(self):
        self.build_requires("cmake/3.31.12", override=True)
        self.tool_requires("protobuf/5.29.3")
        self.tool_requires("yaff/0.0.0@local/local")

        self.test_requires("gtest/1.18.0")

        if self.settings.os != "Windows":
            self.build_requires("meson/1.10.2", override=True)

    def generate(self):
        tc = CMakeToolchain(self)
        tc.variables["FPTN_VERSION"] = FPTN_VERSION
        if self.options.with_gui_client:
            tc.variables["FPTN_BUILD_WITH_GUI_CLIENT"] = "True"
        if self.options.build_only_fptn_lib:
            tc.variables["FPTN_BUILD_ONLY_FPTN_LIB"] = "True"
        if self.options.openwrt:
            tc.variables["FPTN_OPENWRT"] = "True"
        if self._use_mimalloc():
            tc.variables["FPTN_WITH_MIMALLOC"] = "True"

        # setup protobuf compiler
        protobuf_build = self.dependencies.build["protobuf"]
        protoc_path = os.path.join(protobuf_build.package_folder, "bin", "protoc")
        tc.cache_variables["Protobuf_PROTOC_EXECUTABLE"] = protoc_path
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        if self.options.build_only_fptn_lib:
            copy(
                self,
                "*.h",
                src=os.path.join(self.source_folder, "src", "fptn-protocol-lib"),
                dst=os.path.join(self.package_folder, "include", "fptn"),
            )
            copy(
                self,
                "*.h",
                src=os.path.join(self.source_folder, "src", "common"),
                dst=os.path.join(self.package_folder, "include", "fptn", "common"),
            )
            copy(
                self,
                "*.h",
                src=os.path.join(self.build_folder, "src", "fptn-protocol-lib", "protobuf"),
                dst=os.path.join(self.package_folder, "include", "fptn", "protobuf"),
            )
            # copy lib
            copy(
                self,
                "*.a",
                src=os.path.join(self.build_folder, "src", "fptn-protocol-lib"),
                dst=os.path.join(self.package_folder, "lib"),
            )
            copy(
                self,
                "*.lib",
                src=os.path.join(self.build_folder, "src", "fptn-protocol-lib"),
                dst=os.path.join(self.package_folder, "lib"),
            )
            ntp_client_build_include = os.path.join(self.build_folder, "_deps", "ntp_client-src", "include")
            # copy NTP depends
            if os.path.exists(ntp_client_build_include):
                copy(
                    self,
                    "*.h",
                    src=ntp_client_build_include,
                    dst=os.path.join(self.package_folder, "include", "ntp_client"),
                )
            ntp_client_lib_src = os.path.join(self.build_folder, "_deps", "ntp_client-build")
            if os.path.exists(ntp_client_lib_src):
                copy(
                    self,
                    "*.a",
                    src=ntp_client_lib_src,
                    dst=os.path.join(self.package_folder, "lib"),
                )
                copy(
                    self,
                    "*.lib",
                    src=ntp_client_lib_src,
                    dst=os.path.join(self.package_folder, "lib"),
                )
            # copy camouflage-tls depends
            camouflage_tls_build_include = os.path.join(self.build_folder, "_deps", "camouflagetls-src", "include")
            if os.path.exists(camouflage_tls_build_include):
                copy(
                    self,
                    "*.h",
                    src=camouflage_tls_build_include,
                    dst=os.path.join(self.package_folder, "include", "camouflage"),
                )
            camouflage_tls_lib_src = os.path.join(self.build_folder, "_deps", "camouflagetls-build")
            if os.path.exists(camouflage_tls_lib_src):
                copy(
                    self,
                    "*.a",
                    src=camouflage_tls_lib_src,
                    dst=os.path.join(self.package_folder, "lib"),
                )
                copy(
                    self,
                    "*.lib",
                    src=camouflage_tls_lib_src,
                    dst=os.path.join(self.package_folder, "lib"),
                )
            # absorb yaff (runtime lib + headers), since it is a private dependency
            yaff_pkg = self.dependencies["yaff"].package_folder
            copy(
                self,
                "*.a",
                src=os.path.join(yaff_pkg, "lib"),
                dst=os.path.join(self.package_folder, "lib"),
                keep_path=False,
            )
            copy(
                self,
                "*.lib",
                src=os.path.join(yaff_pkg, "lib"),
                dst=os.path.join(self.package_folder, "lib"),
                keep_path=False,
            )
            copy(
                self,
                "*.h",
                src=os.path.join(yaff_pkg, "include"),
                dst=os.path.join(self.package_folder, "include"),
            )

    def package_info(self):
        if self.options.build_only_fptn_lib:
            self.cpp_info.libs = [
                "fptn-protocol-lib_static",
                "ntp_client",
                "camouflage-tls",
                "yaff_proto",
            ]
            self.cpp_info.includedirs = ["include"]
            self.cpp_info.libdirs = ["lib"]

            self.cpp_info.set_property("cmake_file_name", "fptn")
            self.cpp_info.set_property("cmake_target_name", "fptn::fptn")
            self.cpp_info.set_property("cmake_find_mode", "both")

            # Add depends
            self.cpp_info.requires = [
                "argparse::argparse",
                "cpp-httplib::cpp-httplib",
                "boost::boost",
                "fmt::fmt",
                "jwt-cpp::jwt-cpp",
                "nlohmann_json::nlohmann_json",
                "protobuf::protobuf",
                "spdlog::spdlog",
                "zlib::zlib",
                "re2::re2",
                "brotli::brotli",
            ]
            if self._use_mimalloc():
                self.cpp_info.requires.append("mimalloc::mimalloc")
            if self.settings.os == "iOS":
                self.cpp_info.frameworks = ["Security", "CFNetwork", "SystemConfiguration"]
                self.cpp_info.system_libs = ["resolv"]

    def config_options(self):
        if self.settings.os == "Windows":
            self.options.rm_safe("fPIC")
        if self.settings.os in ["iOS", "tvOS", "Android"] or self.options.build_only_fptn_lib:
            self.options["boost"].without_process = True

    def export(self):
        copy(self, f"*", src=self.recipe_folder, dst=self.export_folder)

    def _use_mimalloc(self):
        # mimalloc causes crashes on other platform
        return self.settings.os != "Windows" and (self.settings.arch == "x86_64" or self.settings.os == "Macos")

    def _register_local_recipe(self, recipe, name, version, override=False, force=False, visible=True):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        recipe_rel_path = os.path.join(script_dir, ".conan", "recipes", recipe)
        subprocess.run(
            [
                "conan",
                "export",
                recipe_rel_path,
                f"--name={name}",
                f"--version={version}",
                "--user=local",
                "--channel=local",
            ],
            check=True,
        )
        self.requires(f"{name}/{version}@local/local", override=override, force=force, visible=visible)
