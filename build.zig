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

const Project = struct {
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,

    zydis: *std.Build.Step.Compile,
    safetyhook: *std.Build.Step.Compile,

    fn create(b: *std.Build) Project {
        const target = b.resolveTargetQuery(.{
            .cpu_arch = .x86_64,
            .os_tag = .windows,
            .abi = .gnu,
        });
        const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSmall });

        // Build zydis

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

        // Build safetyhook

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

        const proj = Project{
            .b = b,
            .target = target,
            .optimize = optimize,
            .zydis = zydis_lib,
            .safetyhook = safetyhook,
        };

        return proj;
    }

    fn add_example(self: *const Project, comptime name: []const u8) void {
        const example = self.b.addExecutable(.{
            .name = name,
            .root_module = self.b.createModule(.{
                .target = self.target,
                .optimize = self.optimize,
                .root_source_file = self.b.path("examples/" ++ name ++ ".zig"),
            }),
        });

        example.root_module.addImport("safetyhook", self.safetyhook.root_module);
        self.b.installArtifact(example);
    }
};

pub fn build(b: *std.Build) !void {
    const proj = Project.create(b);

    proj.add_example("mid-hook");
}
