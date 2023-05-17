const std = @import("std");

const Error = error {
    WrongArgsNum,
    WrongKey,
    WrongInputFile,
    WrongOutputFile,
    WrongArg,
    FileWritingError
};

fn printHelp() void {
    std.log.info(
        "[usage] LSFR [-d] -s[x] <seed> -l <sr_register_length_in_bits> -p[x] <polynomial> -i <input_file_path> -o <output_file_path\n" ++
        "   -x    : hex format\n" ++
        "   -d    : decrypt(default encrypt)\n" ++
        "  --help : print this message", .{}
    );
}

const AlgorithmDescriptor = struct {
    lsfr: std.bit_set.DynamicBitSetUnmanaged,
    polynomial: std.bit_set.DynamicBitSetUnmanaged,
    len: usize,
    input_file: std.fs.File,
    output_file: std.fs.File,
};

fn parseArgs(allocator: std.mem.Allocator, args: [][:0]u8) !AlgorithmDescriptor {
    if (args.len > 12 or args.len < 11) {
        printHelp();
        return error.WrongArgsNum;
    }

    const decrypt = std.mem.eql(u8, args[1], "-d");

    if (decrypt and args.len != 12) {
        printHelp();
        return error.WrongArgsNum;
    }

    if (!std.mem.eql(u8, args[1 + @as(usize, @boolToInt(decrypt))][0..2], "-s")) {
        printHelp();
        return error.WrongArg;
    }
    const seed_in_hex = std.mem.eql(u8, args[1 + @as(usize, @boolToInt(decrypt))], "-sx");
    const seed_str = args[2 + @as(usize, @boolToInt(decrypt))];

    if (!std.mem.eql(u8, args[3 + @as(usize, @boolToInt(decrypt))], "-l")) {
        printHelp();
        return error.WrongArg;
    }
    const len = try std.fmt.parseInt(usize, args[4 + @as(usize, @boolToInt(decrypt))][0..], 10);
    
    if (!std.mem.eql(u8, args[5 + @as(usize, @boolToInt(decrypt))][0..2], "-p")) {
        printHelp();
        return error.WrongArg;
    }
    const polynomial_in_hex = std.mem.eql(u8, args[5 + @as(usize, @boolToInt(decrypt))], "-px");
    const polynomial_str = args[6 + @as(usize, @boolToInt(decrypt))];


    const TMP = struct {
        in_hex: bool,
        str: []u8,
        bitset: std.DynamicBitSetUnmanaged,
    };

    var tmp = [_]TMP{
        .{ 
            .in_hex = seed_in_hex, 
            .str = seed_str[0..], 
            .bitset = try std.DynamicBitSetUnmanaged.initEmpty(allocator, len) 
        },
        .{ 
            .in_hex = polynomial_in_hex, 
            .str = polynomial_str[0..], 
            .bitset = try std.DynamicBitSetUnmanaged.initEmpty(allocator, len) 
        },
    };
    for (&tmp) |*value| {
        var i: usize = 0;
        const divider: usize = if (value.*.in_hex) 4 else 8;
        if (((len - 1) / divider) >= value.*.str.len) {
            printHelp();
            return error.WrongArg;
        }
        while (i < len) : (i += 1) {
            const i_rev = len - 1 - i;
            if ((value.*.str[i_rev / divider] & (@as(u8, 1) << @intCast(u3, i_rev % divider))) > 0) {
                value.*.bitset.set(i);
            }
        }
    }

    if (!std.mem.eql(u8, args[7 + @as(usize, @boolToInt(decrypt))], "-i")) {
        printHelp();
        return error.WrongArg;
    }
    
    const input_file = std.fs.cwd().openFileZ(
        args[8 + @as(usize, @boolToInt(decrypt))], 
        .{ .mode = .read_only }
    ) catch {
        printHelp();
        return error.WrongInputFile;
    };

    if (!std.mem.eql(u8, args[9 + @as(usize, @boolToInt(decrypt))], "-o")) {
        printHelp();
        return error.WrongArg;
    }

    const output_file = std.fs.cwd().createFileZ(
        args[10 + @as(usize, @boolToInt(decrypt))], 
        .{ .truncate = true }
    ) catch {
        printHelp();
        return error.WrongOutputFile;
    };

    return AlgorithmDescriptor{
        .lsfr = tmp[0].bitset,
        .polynomial = tmp[1].bitset,
        .len = len,
        .input_file = input_file,
        .output_file = output_file,
    };
}

fn rShift(bitset: *std.DynamicBitSetUnmanaged) void {
    const MaskType = std.DynamicBitSetUnmanaged.MaskInt;
    // const ShiftType = std.DynamicBitSetUnmanaged.ShiftInt;

    bitset.masks[0] >>= 1;

    var i: usize = 1;
    const len = (bitset.bit_length / @bitSizeOf(MaskType)) + @boolToInt((bitset.bit_length % @bitSizeOf(MaskType)) != 0);
    while (i < len) {
        bitset.masks[i-1] |= (bitset.masks[i] & @as(MaskType, 1)) << (@bitSizeOf(MaskType) - 1);
        bitset.masks[i] >>= 1;
    }
}

fn generateBit(lsfr: *std.DynamicBitSetUnmanaged, polynomial: *std.DynamicBitSetUnmanaged) void {
    var poly_iterator = polynomial.iterator(.{.kind = .set, .direction = .forward});

    var xor_accum: u1 = 0;
    var value: ?usize = poly_iterator.next();
    while (value) |index| {
        xor_accum ^= @boolToInt(lsfr.isSet(index));
        value = poly_iterator.next();
    }

    lsfr.setValue(lsfr.bit_length - 1, xor_accum == 1);
}

fn perform(alg_descriptor: *AlgorithmDescriptor) !void {
    const input_file_reader = alg_descriptor.input_file.reader();
    const output_file_writer = alg_descriptor.output_file.writer();

    var buffer: [256]u8 = .{0} ** 256;
    while (true) {
        const bytes_read = try input_file_reader.read(buffer[0..]);
        
        var i: usize = 0;
        while (i < bytes_read) : (i += 1) {
            var tmp: u8 = 0;
            
            comptime var j: usize = 0;
            inline while (j < 8) : (j += 1) {
                tmp |= (buffer[i] & (1 << j)) ^ (@intCast(u8, alg_descriptor.lsfr.masks[0] & 1) << j); 
                rShift(&alg_descriptor.lsfr);
                generateBit(&alg_descriptor.lsfr, &alg_descriptor.polynomial);
            }

            buffer[i] = tmp;
        }

        const bytes_written = try output_file_writer.write(buffer[0..bytes_read]);
        if (bytes_read != bytes_written) {
            return error.FileWritingError;
        }

        if (bytes_read < buffer.len) {
            return;
        }
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if ((args.len == 2 and std.mem.eql(u8, args[1], "--help"))) {
        printHelp();
        return;
    }
    var alg_descriptor = try parseArgs(allocator, args);
    try perform(&alg_descriptor);

    alg_descriptor.input_file.close();
    alg_descriptor.output_file.close();
    alg_descriptor.lsfr.deinit(allocator);
    alg_descriptor.polynomial.deinit(allocator);
}