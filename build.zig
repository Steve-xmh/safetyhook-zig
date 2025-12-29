const std = @import("std");
const Translator = @import("translate_c").Translator;

fn build_zydis(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step.Compile {
    const zydis = b.dependency("zydis", .{});

    const zydis_lib_c = b.addTranslateC(.{
        .root_source_file = zydis.path("Zydis.h"),
        .optimize = optimize,
        .target = target,
    });

    const zydis_lib = b.addLibrary(.{
        .name = "zydis",
        .linkage = .static,
        .root_module = zydis_lib_c.createModule(),
    });

    zydis_lib.root_module.addCSourceFile(.{
        .file = zydis.path("Zydis.c"),
    });
    zydis_lib.root_module.addIncludePath(zydis.path(""));

    return zydis_lib;
}

pub fn build(b: *std.Build) !void {
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .windows,
        .abi = .gnu,
        .cpu_model = .native,
    });
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe });

    const zydis_lib = build_zydis(b, target, optimize);

    const safetyhook = b.addLibrary(.{
        .name = "safetyhook",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .root_source_file = b.path("src/lib.zig"),
        }),
    });

    safetyhook.root_module.addImport("zydis", zydis_lib.root_module);
    b.installArtifact(safetyhook);
}
