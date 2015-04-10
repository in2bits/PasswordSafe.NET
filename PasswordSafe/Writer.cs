using System;
using System.IO;
using System.Text;

namespace PasswordSafe
{
    internal class Writer
    {
        protected readonly Stream _stream;

        public Writer(Stream stream)
        {
            _stream = stream;
        }

        protected void WriteBytes(byte[] bytes, int dataLength = -1)
        {
            if (dataLength == -1)
                dataLength = bytes.Length;
            _stream.Write(bytes, 0, dataLength);
        }

        public void WriteItem(Item item)
        {
            var fields = item.Fields;
            foreach (var field in fields)
                WriteField(field);
        }

        protected virtual int GetFieldDataBlockSize()
        {
            return Safe.EofBytes.Length;
        }

        public void WriteField(Field field)
        {
            var BS = GetFieldDataBlockSize();

            var block = new byte[BS];
            var blockOffset = 0;

            var data = field.Data;
            var length = data.Length;

            Buffer.BlockCopy(BitConverter.GetBytes((Int32)length), 0, block, blockOffset, sizeof(Int32));
            blockOffset += sizeof (Int32);

            block[blockOffset] = field.Type;
            blockOffset++;

            var blockDataLength = Math.Min(BS - blockOffset, length);
            var dataOffset = 0;
            do
            {
                Buffer.BlockCopy(data, dataOffset, block, blockOffset, blockDataLength);
                ProcessFieldDataBlock(block, blockOffset, blockDataLength);
                WriteBytes(block);

                dataOffset += blockDataLength;
                if (dataOffset < length)
                {
                    block = new byte[BS];
                    blockOffset = 0;
                    blockDataLength = Math.Min(BS, length - dataOffset);
                }
            } while (dataOffset < length);
        }

        protected virtual void ProcessFieldDataBlock(byte[] block, int dataOffset, int dataLength)
        {
            //no-op
        }

        public virtual void WriteEof()
        {
            WriteBytes(Safe.EofBytes);
        }
    }
}