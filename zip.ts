// Tom Robinson
// Kris Kowal

import INFLATE from './inflate'
import bops from 'bops'

const LOCAL_FILE_HEADER = 0x04034b50;
const CENTRAL_DIRECTORY_FILE_HEADER = 0x02014b50;
const END_OF_CENTRAL_DIRECTORY_RECORD = 0x06054b50;
const MADE_BY_UNIX = 3;     // See http://www.pkware.com/documents/casestudies/APPNOTE.TXT

class BufferSource {
    constructor(
        private readonly buffer: any
    ) {
    }
    read(start: number, length: number) {
        return bops.subarray(this.buffer, start, start + length);
    }

    length() {
        return this.buffer.length;
    }
}

export class Reader {
    private _source: BufferSource
    private _offset: number

    constructor(data) {
        if (!(this instanceof Reader)) {
            return new Reader(data);
        }
    	this._source = new BufferSource(data);
        this._offset = 0;
    }

    length () {
    	return this._source.length();
    }

    position () {
        return this._offset;
    }

    seek (offset: number) {
        this._offset = offset;
    }

    read (length: number) {
    	var bytes = this._source.read(this._offset, length);
    	this._offset += length;
    	return bytes;
    }

    readInteger (length: number, bigEndian: boolean = false) {
        if (bigEndian)
            return bytesToNumberBE(this.read(length));
        else
            return bytesToNumberLE(this.read(length));
    }

    readString (length: number, charset?: number) {
        return bops.to(this.read(length), charset || "utf8");
    }

    readUncompressed (length: number, method: number) {
        var compressed = this.read(length);
        var uncompressed = null;
        if (method === 0)
            uncompressed = compressed;
        else if (method === 8)
            uncompressed = INFLATE.inflate(compressed);
        else
            throw new Error("Unknown compression method");
        return uncompressed;
    }

    readStructure () {
        var stream = this;
        var structure = {};

        // local file header signature     4 bytes  (0x04034b50)
        structure.signature = stream.readInteger(4);

        switch (structure.signature) {
            case LOCAL_FILE_HEADER :
                this.readLocalFileHeader(structure);
                break;
            case CENTRAL_DIRECTORY_FILE_HEADER :
                this.readCentralDirectoryFileHeader(structure);
                break;
            case END_OF_CENTRAL_DIRECTORY_RECORD :
                this.readEndOfCentralDirectoryRecord(structure);
                break;
            default:
                throw new Error("Unknown ZIP structure signature: 0x" + structure.signature.toString(16));
        }

        return structure;
    }

    // ZIP local file header
    // Offset   Bytes   Description
    // 0        4       Local file header signature = 0x04034b50
    // 4        2       Version needed to extract (minimum)
    // 6        2       General purpose bit flag
    // 8        2       Compression method
    // 10       2       File last modification time
    // 12       2       File last modification date
    // 14       4       CRC-32
    // 18       4       Compressed size
    // 22       4       Uncompressed size
    // 26       2       File name length (n)
    // 28       2       Extra field length (m)
    // 30       n       File name
    // 30+n     m       Extra field
    readLocalFileHeader (structure) {
        var stream = this;
        structure = structure || {};

        if (!structure.signature)
            structure.signature = stream.readInteger(4);    // Local file header signature = 0x04034b50

        if (structure.signature !== LOCAL_FILE_HEADER)
            throw new Error("ZIP local file header signature invalid (expects 0x04034b50, actually 0x" + structure.signature.toString(16) +")");

        structure.version_needed       = stream.readInteger(2);    // Version needed to extract (minimum)
        structure.flags                = stream.readInteger(2);    // General purpose bit flag
        structure.compression_method   = stream.readInteger(2);    // Compression method
        structure.last_mod_file_time   = stream.readInteger(2);    // File last modification time
        structure.last_mod_file_date   = stream.readInteger(2);    // File last modification date
        structure.crc_32               = stream.readInteger(4);    // CRC-32
        structure.compressed_size      = stream.readInteger(4);    // Compressed size
        structure.uncompressed_size    = stream.readInteger(4);    // Uncompressed size
        structure.file_name_length     = stream.readInteger(2);    // File name length (n)
        structure.extra_field_length   = stream.readInteger(2);    // Extra field length (m)

        var n = structure.file_name_length;
        var m = structure.extra_field_length;

        structure.file_name            = stream.readString(n);     // File name
        structure.extra_field          = stream.read(m);           // Extra fieldFile name

        return structure;
    }

    // ZIP central directory file header
    // Offset   Bytes   Description
    // 0        4       Central directory file header signature = 0x02014b50
    // 4        2       Version made by
    // 6        2       Version needed to extract (minimum)
    // 8        2       General purpose bit flag
    // 10       2       Compression method
    // 12       2       File last modification time
    // 14       2       File last modification date
    // 16       4       CRC-32
    // 20       4       Compressed size
    // 24       4       Uncompressed size
    // 28       2       File name length (n)
    // 30       2       Extra field length (m)
    // 32       2       File comment length (k)
    // 34       2       Disk number where file starts
    // 36       2       Internal file attributes
    // 38       4       External file attributes
    // 42       4       Relative offset of local file header
    // 46       n       File name
    // 46+n     m       Extra field
    // 46+n+m   k       File comment
    readCentralDirectoryFileHeader (structure) {
        var stream = this;
        structure = structure || {};

        if (!structure.signature)
            structure.signature = stream.readInteger(4); // Central directory file header signature = 0x02014b50

        if (structure.signature !== CENTRAL_DIRECTORY_FILE_HEADER)
            throw new Error("ZIP central directory file header signature invalid (expects 0x02014b50, actually 0x" + structure.signature.toString(16) +")");

        structure.version                   = stream.readInteger(2);    // Version made by
        structure.version_needed            = stream.readInteger(2);    // Version needed to extract (minimum)
        structure.flags                     = stream.readInteger(2);    // General purpose bit flag
        structure.compression_method        = stream.readInteger(2);    // Compression method
        structure.last_mod_file_time        = stream.readInteger(2);    // File last modification time
        structure.last_mod_file_date        = stream.readInteger(2);    // File last modification date
        structure.crc_32                    = stream.readInteger(4);    // CRC-32
        structure.compressed_size           = stream.readInteger(4);    // Compressed size
        structure.uncompressed_size         = stream.readInteger(4);    // Uncompressed size
        structure.file_name_length          = stream.readInteger(2);    // File name length (n)
        structure.extra_field_length        = stream.readInteger(2);    // Extra field length (m)
        structure.file_comment_length       = stream.readInteger(2);    // File comment length (k)
        structure.disk_number               = stream.readInteger(2);    // Disk number where file starts
        structure.internal_file_attributes  = stream.readInteger(2);    // Internal file attributes
        structure.external_file_attributes  = stream.readInteger(4);    // External file attributes
        structure.local_file_header_offset  = stream.readInteger(4);    // Relative offset of local file header

        var n = structure.file_name_length;
        var m = structure.extra_field_length;
        var k = structure.file_comment_length;

        structure.file_name                 = stream.readString(n);     // File name
        structure.extra_field               = stream.read(m);           // Extra field
        structure.file_comment              = stream.readString(k);     // File comment
        structure.mode                      = stream.detectChmod(structure.version, structure.external_file_attributes); // chmod

        return structure;
    }

    detectChmod(versionMadeBy, externalFileAttributes) {
        var madeBy = versionMadeBy >> 8,
            mode = externalFileAttributes >>> 16,
            chmod = false;

        mode = (mode & 0x1ff);
        if (madeBy === MADE_BY_UNIX && (process.platform === 'darwin' || process.platform === 'linux')) {
            chmod = mode.toString(8);
        }
        return chmod;
    }

    // finds the end of central directory record
    // I'd like to slap whoever thought it was a good idea to put a variable length comment field here
    locateEndOfCentralDirectoryRecord () {
        var length = this.length();
        var minPosition = length - Math.pow(2, 16) - 22;

        var position = length - 22 + 1;
        while (--position) {
            if (position < minPosition)
                throw new Error("Unable to find end of central directory record");

            this.seek(position);
            var possibleSignature = this.readInteger(4);
            if (possibleSignature !== END_OF_CENTRAL_DIRECTORY_RECORD)
                continue;

            this.seek(position + 20);
            var possibleFileCommentLength = this.readInteger(2);
            if (position + 22 + possibleFileCommentLength === length)
                break;
        }

        this.seek(position);
        return position;
    };

    // ZIP end of central directory record
    // Offset   Bytes   Description
    // 0        4       End of central directory signature = 0x06054b50
    // 4        2       Number of this disk
    // 6        2       Disk where central directory starts
    // 8        2       Number of central directory records on this disk
    // 10       2       Total number of central directory records
    // 12       4       Size of central directory (bytes)
    // 16       4       Offset of start of central directory, relative to start of archive
    // 20       2       ZIP file comment length (n)
    // 22       n       ZIP file comment
    readEndOfCentralDirectoryRecord (structure) {
        var stream = this;
        structure = structure || {};

        if (!structure.signature)
            structure.signature = stream.readInteger(4); // End of central directory signature = 0x06054b50

        if (structure.signature !== END_OF_CENTRAL_DIRECTORY_RECORD)
            throw new Error("ZIP end of central directory record signature invalid (expects 0x06054b50, actually 0x" + structure.signature.toString(16) +")");

        structure.disk_number               = stream.readInteger(2);    // Number of this disk
        structure.central_dir_disk_number   = stream.readInteger(2);    // Disk where central directory starts
        structure.central_dir_disk_records  = stream.readInteger(2);    // Number of central directory records on this disk
        structure.central_dir_total_records = stream.readInteger(2);    // Total number of central directory records
        structure.central_dir_size          = stream.readInteger(4);    // Size of central directory (bytes)
        structure.central_dir_offset        = stream.readInteger(4);    // Offset of start of central directory, relative to start of archive
        structure.file_comment_length       = stream.readInteger(2);    // ZIP file comment length (n)

        var n = structure.file_comment_length;

        structure.file_comment              = stream.readString(n);     // ZIP file comment

        return structure;
    }

    readDataDescriptor () {
        var stream = this;
        var descriptor = {};

        descriptor.crc_32 = stream.readInteger(4);
        if (descriptor.crc_32 === 0x08074b50)
            descriptor.crc_32 = stream.readInteger(4); // CRC-32

        descriptor.compressed_size          = stream.readInteger(4);    // Compressed size
        descriptor.uncompressed_size        = stream.readInteger(4);    // Uncompressed size

        return descriptor;
    }

    iterator () {
        var stream = this;

        // find the end record and read it
        stream.locateEndOfCentralDirectoryRecord();
        var endRecord = stream.readEndOfCentralDirectoryRecord();

        // seek to the beginning of the central directory
        stream.seek(endRecord.central_dir_offset);

        var count = endRecord.central_dir_disk_records;

        return {
            next: function () {
                if ((count--) === 0)
                    throw "stop-iteration";

                // read the central directory header
                var centralHeader = stream.readCentralDirectoryFileHeader();

                // save our new position so we can restore it
                var saved = stream.position();

                // seek to the local header and read it
                stream.seek(centralHeader.local_file_header_offset);
                var localHeader = stream.readLocalFileHeader();

    			// dont read the content just save the position for later use
    			var start = stream.position();

                // seek back to the next central directory header
                stream.seek(saved);

                return new Entry(localHeader, stream, start, centralHeader.compressed_size, centralHeader.compression_method, centralHeader.mode);
            }
        };
    };

    forEach (block: Function, context: any = null) {
        var iterator = this.iterator();
        var next;
        while (true) {
            try {
                next = iterator.next();
            } catch (exception) {
                if (exception === "stop-iteration")
                    break;
                if (exception === "skip-iteration")
                    continue;
                throw exception;
            }
            block.call(context, next);
        }
    };

    toObject (charset) {
        var object = {};
        this.forEach(function (entry) {
            if (entry.isFile()) {
                var data = entry.getData();
                if (charset)
                    data = data.toString(charset);
                object[entry.getName()] = data;
            }
        });
        return object;
    };
}

export class Entry {
    constructor(header, realStream, start, compressedSize, compressionMethod, mode) {
        this._mode = mode;
        this._header = header;
    	this._realStream = realStream;
        this._stream = null;
    	this._start = start;
    	this._compressedSize = compressedSize;
    	this._compressionMethod = compressionMethod;
    }

    getName() {
        return this._header.file_name;
    };

    isFile() {
        return !this.isDirectory();
    };

    isDirectory() {
        return this.getName().slice(-1) === "/";
    };

    lastModified() {
        return decodeDateTime(this._header.last_mod_file_date, this._header.last_mod_file_time);
    };

    getData() {
    	if (this._stream == null) {
    		var bookmark = this._realStream.position();
    		this._realStream.seek(this._start);
    		this._stream = this._realStream.readUncompressed(this._compressedSize, this._compressionMethod);
    		this._realStream.seek(bookmark);
    	}
        return this._stream;
    };

    getMode() {
        return this._mode;
    };
};

function bytesToNumberLE(bytes) {
    var acc = 0;
    for (var i = 0; i < bytes.length; i++)
        acc += bops.readUInt8(bytes, i) << (8*i);
    return acc;
};

function bytesToNumberBE(bytes) {
    var acc = 0;
    for (var i = 0; i < bytes.length; i++)
        acc = (acc << 8) + bops.readUInt8(bytes, i);
    return acc;
};

function numberToBytesLE(number, length) {
    var bytes: number[] = [];
    for (var i = 0; i < length; i++)
        bytes[i] = (number >> (8*i)) & 0xFF;
    return new bops.from(bytes);
};

function numberToBytesBE(number, length) {
    var bytes: number[] = [];
    for (var i = 0; i < length; i++)
        bytes[length-i-1] = (number >> (8*i)) & 0xFF;
    return new bops.from(bytes);
};

function decodeDateTime(date, time) {
    return new Date(
        (date >>> 9) + 1980,
        ((date >>> 5) & 15) - 1,
        (date) & 31,
        (time >>> 11) & 31,
        (time >>> 5) & 63,
        (time & 63) * 2
    );
}

