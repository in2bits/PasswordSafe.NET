using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace PasswordSafe
{
    internal class Reader
    {
        private readonly BinaryReader _reader;

        public Reader(Stream stream)
        {
            _reader = new BinaryReader(stream, Encoding.UTF8);
        }

        public byte[] ReadBytes(int count)
        {
            return _reader.ReadBytes(count);
        }

        public void AssertNextBytesEqual(byte[] reference)
        {
            var buffer = ReadBytes(reference.Length);
            ByteUtil.AssertBytesEqual(buffer, reference);
        }

        public UInt32 ReadUInt32()
        {
            return _reader.ReadUInt32();
        }

        public Item ReadItem()
        {
            var fields = ReadFieldsToEnd().ToList();
            if (fields.Count == 1 && fields[0] == Field.Eof)
                return Item.Eof;
            else if (fields.Count == 0)
                return Item.Eof;
            var item = Item.From(fields);
            return item;
        }

        public IEnumerable<Field> ReadFieldsToEnd()
        {
            var fields = new List<Field>();

            var emergencyExit = 255;

            //FieldTypes type;
            Field field;
            do
            {
                try
                {
                    field = ReadField();
                    if (field.Type == Field.Eof.Type)
                        return fields;
                    fields.Add(field);
                }
                catch (Exception)
                {
                    break;
                }
            } while (field.Type != Field.Eof.Type && --emergencyExit > 0);

            return fields;
        }

        private Field ReadField()
        {
            byte type;
            bool eof;

            var data = ReadFieldData(out type, out eof);

            if (eof)
                return Field.Eof;

            var field = new Field(type)
                {
                    Data = data,
                };
            return field;
        }

        protected virtual int GetFieldDataBlockSize()
        {
            return Safe.EofBytes.Length;
        }

        protected virtual void ProcessFieldDataBlock(byte[] block)
        {
            //no-op
        }

        protected byte[] ReadFieldData(out byte type, out bool eof)
        {
            type = 0;
            eof = false;

            var BS = GetFieldDataBlockSize();
            var block = ReadBytes(BS);

            if (ByteUtil.AreBytesEqual(block, Safe.EofBytes))
            {
                eof = true;
                return null;
            }

            ProcessFieldDataBlock(block);
            var length = BitConverter.ToInt32(block, 0);
            type = block[sizeof(Int32)];
            var buffer = new byte[length];

            if (length == 0)
                return buffer;

            var blockOffset = sizeof(Int32) + 1;
            var blockDataLength = Math.Min(BS - blockOffset, length);
            var bufferOffset = 0;
            do
            {
                Buffer.BlockCopy(block, blockOffset, buffer, bufferOffset, blockDataLength);
                bufferOffset += blockDataLength;
                if (bufferOffset < length)
                {
                    block = ReadBytes(BS);
                    blockOffset = 0;
                    ProcessFieldDataBlock(block);
                    blockDataLength = Math.Min(BS, length - bufferOffset);
                }
            } while (bufferOffset < length);

            return buffer;
        }

        public virtual void ReadHmac()
        {

        }
    }
}