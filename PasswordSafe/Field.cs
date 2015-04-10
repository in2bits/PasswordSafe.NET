namespace PasswordSafe
{
    public class Field
    {
        private readonly byte _type;

        public Field(byte type)
        {
            _type = type;
        }

        public byte Type { get { return _type; } }
        public byte[] Data { get; set; }

        public static readonly Field Eof = new Field(0xff){Data=new byte[0]};
    }
}