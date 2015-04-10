using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PasswordSafe
{
    internal enum FieldTypes
    {
        Start = 0x00,
        Name = 0x00,
        Uuid = 0x01,
        Group = 0x02,
        Title = 0x03,
        User = 0x04,
        Notes = 0x05,
        Password = 0x06,
        CreatedTime = 0x07,
        PasswordModified = 0x08,
        AccessTime = 0x09,
        PasswordExpires = 0x0a,
        Reserved = 0x0b,
        RecordModifiedTime = 0x0c,
        Url = 0x0d, 
        Autotype = 0x0e,
        PasswordHistory = 0x0f,
        Policy = 0x10,
        XtimeInt = 0x11,
        RunCommand = 0x12,
        DoubleClickAction = 0x13,
        Email = 0x14,
        Protected = 0x15,
        Symbols = 0x16,
        ShiftDoubleClickAction = 0x17,
        PolicyName = 0x18,
        KeyboardShortcuts = 0x19,
        //Last,
        End = 0xff,

        // Internal fields only - used in filters
        EntrySize = 0x100, 
        EntryType = 0x101, 
        EntryStatus = 0x102, 
        PasswordLength = 0x103,
        
        // 'UNKNOWNFIELDS' should be last
        UnknownFields = 0x104
    }
}
