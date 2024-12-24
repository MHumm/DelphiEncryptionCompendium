{*****************************************************************************
  The DEC team (see file NOTICE.txt) licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License. A copy of this licence is found in the root directory
  of this project in the file LICENCE.txt or alternatively at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing,
  software distributed under the License is distributed on an
  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  KIND, either express or implied.  See the License for the
  specific language governing permissions and limitations
  under the License.
*****************************************************************************}
unit DECCipherInterface;

interface

uses
  {$IFDEF FPC}
  SysUtils, Classes,
  {$ELSE}
  System.SysUtils, System.Classes,
  {$ENDIF}
  DECTypes, DECCipherBase, DECFormatBase;

type
  /// <summary>
  ///   Common interface for all ciphers. Some ciphers may have additional
  ///   methods/properties though!
  /// </summary>
  IDECCipher = Interface
  ['{73D70F28-95C0-4715-8C27-1AE6FBEE9698}']
    /// <summary>
    ///   Encrypts the contents of a given byte array
    /// </summary>
    /// <param name="Source">
    ///   Byte array with data to be encrypted
    /// </param>
    /// <returns>
    ///   Byte array with encrypted data
    /// </returns>
    function EncodeBytes(const Source: TBytes): TBytes;

    /// <summary>
    ///   Decrypts the contents of a given byte array
    /// </summary>
    /// <param name="Source">
    ///   Byte array with data to be decrypted
    /// </param>
    /// <returns>
    ///   Byte array with decrypted data
    /// </returns>
    function DecodeBytes(const Source: TBytes): TBytes;

    /// <summary>
    ///   Encrypts the data contained in a given stream
    /// </summary>
    /// <param name="Source">
    ///   Source stream containing the data to encrypt
    /// </param>
    /// <param name="Dest">
    ///   Destination stream, where the encrypted data shall be put in
    /// </param>
    /// <param name="DataSize">
    ///   Number of bytes of Source to be encrypted
    /// </param>
    /// <param name="OnProgress">
    ///   optional callback for reporting progress of the operation
    /// </param>
    procedure EncodeStream(const Source, Dest: TStream; DataSize: Int64;
                           const OnProgress: TDECProgressEvent = nil);

    /// <summary>
    ///   Decrypts the data contained in a given stream
    /// </summary>
    /// <param name="Source">
    ///   Source stream containing the data to decrypt
    /// </param>
    /// <param name="Dest">
    ///   Destination stream, where the decrypted data shall be put in
    /// </param>
    /// <param name="DataSize">
    ///   Number of bytes of Source to be decrypted
    /// </param>
    /// <param name="OnProgress">
    ///   optional callback for reporting progress of the operation
    /// </param>
    procedure DecodeStream(const Source, Dest: TStream; DataSize: Int64;
                           const OnProgress: TDECProgressEvent = nil);

    /// <summary>
    ///   Reads the contents of one file, encrypts it and stores it in another file
    /// </summary>
    /// <param name="SourceFileName">
    ///   Path and name of the file to encrypt
    /// </param>
    /// <param name="DestFileName">
    ///   Path and name of the file the encrypted data shall be stored in
    /// </param>
    /// <param name="OnProgress">
    ///   Optional event which can be passed to get information about the
    ///   progress of the encryption operation
    /// </param>
    procedure EncodeFile(const SourceFileName, DestFileName: string;
                         const OnProgress: TDECProgressEvent = nil);

    /// <summary>
    ///   Reads the contents of one file, decrypts it and stores it in another file
    /// </summary>
    /// <param name="SourceFileName">
    ///   Path and name of the file to decrypt
    /// </param>
    /// <param name="DestFileName">
    ///   Path and name of the file the decrypted data shall be stored in
    /// </param>
    /// <param name="OnProgress">
    ///   Optional event which can be passed to get information about the
    ///   progress of the decryption operation
    /// </param>
    procedure DecodeFile(const SourceFileName, DestFileName: string;
                         const OnProgress: TDECProgressEvent = nil);

    /// <summary>
    ///   Encrypts the contents of the passed unicode string
    /// </summary>
    /// <param name="Source">
    ///   String to encrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Encoded will be the encrypted data, not the
    ///   source data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Encrypted string as a byte array
    /// </returns>
    function EncodeStringToBytes(const Source: string; Format: TDECFormatClass = nil): TBytes; overload;

    /// <summary>
    ///   Encrypts the contents of the passed RawByteString
    /// </summary>
    /// <param name="Source">
    ///   String to encrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Encoded will be the encrypted data, not the
    ///   source data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Encrypted string as a byte array
    /// </returns>
    function EncodeStringToBytes(const Source: RawByteString; Format: TDECFormatClass = nil): TBytes; overload;

    /// <summary>
    ///   Encrypts the contents of the passed unicode string
    /// </summary>
    /// <param name="Source">
    ///   String to encrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Encoded will be the encrypted data, not the
    ///   source data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Encrypted string
    /// </returns>
    /// <remarks>
    ///   The use of this method is only recommended if a formatting is passed
    ///   which will result in an 7-bit ASCII compatible string as we cannot
    ///   ensure that Unicode string processing will not alter/interpret some
    ///   byte combinations in a destructive way, making the encrypted string
    ///   un-decryptable.
    /// </remarks>
    function EncodeStringToString(const Source: string; Format: TDECFormatClass = nil): string; overload;

    /// <summary>
    ///   Encrypts the contents of the passed unicode string
    /// </summary>
    /// <param name="Source">
    ///   String to encrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Encoded will be the encrypted data, not the
    ///   source data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Encrypted string
    /// </returns>
    /// <remarks>
    ///   The use of this method is only recommended if a formatting is passed
    ///   which will result in an 7-bit ASCII compatible string as we cannot
    ///   ensure that string processing will not alter/interpret some
    ///   byte combinations in a destructive way, making the encrypted string
    ///   un-decryptable.
    /// </remarks>
    function EncodeStringToString(const Source: RawByteString; Format: TDECFormatClass = nil): RawByteString; overload;

    /// <summary>
    ///   Decrypts the contents of the passed encrypted unicode string
    /// </summary>
    /// <param name="Source">
    ///   String to decrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Decoded will be the still encrypted data, not the
    ///   encrypted data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Decrypted string as a byte array
    /// </returns>
    function DecodeStringToBytes(const Source: string; Format: TDECFormatClass = nil): TBytes; overload;

    /// <summary>
    ///   Decrypts the contents of the passed encrypted RawByteString
    /// </summary>
    /// <param name="Source">
    ///   String to decrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Decoded will be the still encrypted data, not the
    ///   encrypted data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Decrypted string as a byte array
    /// </returns>
    function DecodeStringToBytes(const Source: RawByteString; Format: TDECFormatClass = nil): TBytes; overload;

    /// <summary>
    ///   Decrypts the contents of the passed Unicode string
    /// </summary>
    /// <param name="Source">
    ///   String to decrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Decoded will be the encrypted data, not the
    ///   decrypted data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Decrypted string
    /// </returns>
    /// <remarks>
    ///   The use of this method is only recommended if a formatting is passed
    ///   which uses an 7-bit ASCII compatible string as input so that it
    ///   didn't get altered by Unicode string processing in some hafrmful way
    /// </remarks>
    function DecodeStringToString(const Source: string; Format: TDECFormatClass = nil): string; overload;

    /// <summary>
    ///   Decrypts the contents of the passed RawByteString string
    /// </summary>
    /// <param name="Source">
    ///   String to decrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Decoded will be the encrypted data, not the
    ///   decrypted data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Decrypted string
    /// </returns>
    /// <remarks>
    ///   The use of this method is only recommended if a formatting is passed
    ///   which uses an 7-bit ASCII compatible string as input so that it
    ///   didn't get altered by string processing in some hafrmful way
    /// </remarks>
    function DecodeStringToString(const Source: RawByteString; Format: TDECFormatClass = nil): RawByteString; overload;

{$IFDEF ANSISTRINGSUPPORTED}
    /// <summary>
    ///   Encrypts the contents of the passed Ansistring
    /// </summary>
    /// <param name="Source">
    ///   String to encrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Encoded will be the encrypted data, not the
    ///   source data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Encrypted string as a byte array
    /// </returns>
    function EncodeStringToBytes(const Source: AnsiString; Format: TDECFormatClass = nil): TBytes; overload;

    /// <summary>
    ///   Encrypts the contents of the passed Ansistring
    /// </summary>
    /// <param name="Source">
    ///   String to encrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Encoded will be the encrypted data, not the
    ///   source data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Encrypted string as an AnsiString
    /// </returns>
    /// <remarks>
    ///   The use of this method is only recommended if a formatting is passed
    ///   which will result in an 7-bit ASCII compatible string as we cannot
    ///   ensure that string processing will not alter/interpret some
    ///   byte combinations in a destructive way, making the encrypted string
    ///   un-decryptable.
    /// </remarks>
    function EncodeStringToString(const Source: AnsiString; Format: TDECFormatClass = nil): AnsiString; overload;

    /// <summary>
    ///   Decrypts the contents of the passed encrypted Ansistring
    /// </summary>
    /// <param name="Source">
    ///   String to decrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Decoded will be the still encrypted data, not the
    ///   encrypted data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Decrypted string as a byte array
    /// </returns>
    function DecodeStringToBytes(const Source: AnsiString; Format: TDECFormatClass = nil): TBytes; overload;

    /// <summary>
    ///   Decrypts the contents of the passed AnsiString string
    /// </summary>
    /// <param name="Source">
    ///   String to decrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Decoded will be the encrypted data, not the
    ///   decrypted data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Decrypted string
    /// </returns>
    /// <remarks>
    ///   The use of this method is only recommended if a formatting is passed
    ///   which uses an 7-bit ASCII compatible string as input so that it
    ///   didn't get altered by string processing in some hafrmful way
    /// </remarks>
    function DecodeStringToString(const Source: AnsiString; Format: TDECFormatClass = nil): AnsiString; overload;
{$ENDIF}

{$IFNDEF NEXTGEN}
    /// <summary>
    ///   Encrypts the contents of the passed Widestring
    /// </summary>
    /// <param name="Source">
    ///   String to encrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Encoded will be the encrypted data, not the
    ///   source data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Encrypted string as a byte array
    /// </returns>
    function EncodeStringToBytes(const Source: WideString; Format: TDECFormatClass = nil): TBytes; overload;

    /// <summary>
    ///   Encrypts the contents of the passed Widestring
    /// </summary>
    /// <param name="Source">
    ///   String to encrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Encoded will be the encrypted data, not the
    ///   source data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Encrypted string as an WideString
    /// </returns>
    /// <remarks>
    ///   The use of this method is only recommended if a formatting is passed
    ///   which will result in an 7-bit ASCII compatible string as we cannot
    ///   ensure that string processing will not alter/interpret some
    ///   byte combinations in a destructive way, making the encrypted string
    ///   un-decryptable.
    /// </remarks>
    function EncodeStringToString(const Source: WideString; Format: TDECFormatClass = nil): WideString; overload;

    /// <summary>
    ///   Decrypts the contents of the passed encrypted Widestring
    /// </summary>
    /// <param name="Source">
    ///   String to decrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Decoded will be the still encrypted data, not the
    ///   encrypted data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Decrypted string as a byte array
    /// </returns>
    function DecodeStringToBytes(const Source: WideString; Format: TDECFormatClass = nil): TBytes; overload;

    /// <summary>
    ///   Decrypts the contents of the passed WideString string
    /// </summary>
    /// <param name="Source">
    ///   String to decrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Decoded will be the encrypted data, not the
    ///   decrypted data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Decrypted string
    /// </returns>
    /// <remarks>
    ///   The use of this method is only recommended if a formatting is passed
    ///   which uses an 7-bit ASCII compatible string as input so that it
    ///   didn't get altered by string processing in some hafrmful way
    /// </remarks>
    function DecodeStringToString(const Source: WideString; Format: TDECFormatClass = nil): WideString; overload;
{$ENDIF}

    /// <summary>
    ///   Initializes the cipher with the necessary encryption/decryption key
    /// </summary>
    /// <param name="Key">
    ///   Encryption/decryption key. Recommended/required key length is dependant
    ///   on the concrete algorithm.
    /// </param>
    /// <param name="Size">
    ///   Size of the key in bytes
    /// </param>
    /// <param name="IVector">
    ///   Initialization vector. This contains the values the first block of
    ///   data to be processed is linked with. This is being done the same way
    ///   as the 2nd block of the data to be processed will be linked with the
    ///   first block and so on and this is dependant on the cypher mode set via
    ///   Mode property
    /// </param>
    /// <param name="IVectorSize">
    ///   Size of the initialization vector in bytes
    /// </param>
    /// <param name="IFiller">
    ///   Optional parameter defining the value with which the initialization
    ///   vector is prefilled. So it will contain something defined in any unused
    ///   bytes if a value shorter than the required IV size is given for the IV.
    /// </param>
    /// <param name="PaddingMode">
    ///   optional parameter defining the padding mode instead of using IFiller byte.
    /// </param>
    procedure Init(const Key; Size: Integer; const IVector; IVectorSize: Integer; IFiller: Byte = $FF;
      PaddingMode: TPaddingMode = pmNone); overload;
    /// <summary>
    ///   Initializes the cipher with the necessary encryption/decryption key
    /// </summary>
    /// <param name="Key">
    ///   Encryption/decryption key. Recommended/required key length is dependant
    ///   on the concrete algorithm.
    /// </param>
    /// <param name="IVector">
    ///   Initialization vector. This contains the values the first block of
    ///   data to be processed is linked with. This is being done the same way
    ///   as the 2nd block of the data to be processed will be linked with the
    ///   first block and so on and this is dependant on the cypher mode set via
    ///   Mode property
    /// </param>
    /// <param name="IFiller">
    ///   Optional parameter defining the value with which the initialization
    ///   vector is prefilled. So it will contain something defined in any unused
    ///   bytes if a value shorter than the required IV size is given for the IV.
    /// </param>
    /// <param name="PaddingMode">
    ///   optional parameter defining the padding mode instead of using IFiller byte.
    /// </param>
    procedure Init(const Key: TBytes; const IVector: TBytes; IFiller: Byte = $FF;
      PaddingMode: TPaddingMode = pmNone); overload;
    /// <summary>
    ///   Initializes the cipher with the necessary encryption/decryption key
    /// </summary>
    /// <param name="Key">
    ///   Encryption/decryption key. Recommended/required key length is dependant
    ///   on the concrete algorithm.
    /// </param>
    /// <param name="IVector">
    ///   Initialization vector. This contains the values the first block of
    ///   data to be processed is linked with. This is being done the same way
    ///   as the 2nd block of the data to be processed will be linked with the
    ///   first block and so on and this is dependant on the cypher mode set via
    ///   Mode property
    /// </param>
    /// <param name="IFiller">
    ///   Optional parameter defining the value with which the initialization
    ///   vector is prefilled. So it will contain something defined in any unused
    ///   bytes if a value shorter than the required IV size is given for the IV.
    /// </param>
    /// <param name="PaddingMode">
    ///   optional parameter defining the padding mode instead of using IFiller byte.
    /// </param>
    procedure Init(const Key: RawByteString; const IVector: RawByteString = ''; IFiller: Byte = $FF;
      PaddingMode: TPaddingMode = pmNone); overload;
    {$IFDEF ANSISTRINGSUPPORTED}
    /// <summary>
    ///   Initializes the cipher with the necessary encryption/decryption key.
    ///   Only for use with the classic desktop compilers.
    /// </summary>
    /// <param name="Key">
    ///   Encryption/decryption key. Recommended/required key length is dependant
    ///   on the concrete algorithm.
    /// </param>
    /// <param name="IVector">
    ///   Initialization vector. This contains the values the first block of
    ///   data to be processed is linked with. This is being done the same way
    ///   as the 2nd block of the data to be processed will be linked with the
    ///   first block and so on and this is dependant on the cypher mode set via
    ///   Mode property
    /// </param>
    /// <param name="IFiller">
    ///   Optional parameter defining the value with which the initialization
    ///   vector is prefilled. So it will contain something defined in any unused
    ///   bytes if a value shorter than the required IV size is given for the IV.
    /// </param>
    /// <param name="PaddingMode">
    ///   optional parameter defining the padding mode instead of using IFiller byte.
    /// </param>
    procedure Init(const Key: AnsiString; const IVector: AnsiString = ''; IFiller: Byte = $FF;
      PaddingMode: TPaddingMode = pmNone); overload;
    {$ENDIF}
    {$IFNDEF NEXTGEN}
    /// <summary>
    ///   Initializes the cipher with the necessary encryption/decryption key.
    ///   Only for use with the classic desktop compilers.
    /// </summary>
    /// <param name="Key">
    ///   Encryption/decryption key. Recommended/required key length is dependant
    ///   on the concrete algorithm.
    /// </param>
    /// <param name="IVector">
    ///   Initialization vector. This contains the values the first block of
    ///   data to be processed is linked with. This is being done the same way
    ///   as the 2nd block of the data to be processed will be linked with the
    ///   first block and so on and this is dependant on the cypher mode set via
    ///   Mode property
    /// </param>
    /// <param name="IFiller">
    ///   Optional parameter defining the value with which the initialization
    ///   vector is prefilled. So it will contain something defined in any unused
    ///   bytes if a value shorter than the required IV size is given for the IV.
    /// </param>
    /// <param name="PaddingMode">
    ///   optional parameter defining the padding mode instead of using IFiller byte.
    /// </param>
    procedure Init(const Key: WideString; const IVector: WideString = ''; IFiller: Byte = $FF;
      PaddingMode: TPaddingMode = pmNone); overload;
    {$ENDIF}

    /// <summary>
    ///   Returns the currently set cipher block mode, means how blocks are
    ///   linked to each other in order to avoid certain attacks.
    /// </summary>
    function GetMode: TCipherMode;

    /// <summary>
    ///   Sets the cipher mode, means how each block is being linked with his
    ///   predecessor to avoid certain attacks
    /// </summary>
    procedure SetMode(Value: TCipherMode);

    /// <summary>
    ///   Mode used for padding data to be encrypted/decrypted. See TCipherMode.
    /// </summary>
    property Mode: TCipherMode
      read   GetMode
      write  SetMode;
  end;

  /// <summary>
  ///   Common interface for all authenticated ciphers like GCM mode.
  ///   Some ciphers may have additional methods/properties though!
  /// </summary>
  IDECAuthenticatedCipher = Interface
  ['{506A865D-9461-4038-BAB7-A013A9321E8E}']
    /// <summary>
    ///   Returns the data which shall get authenticated when using a cipher
    ///   mode which provides authentication support as well.
    /// </summary>
    /// <returns>
    ///   Data to be authenticated. Raises an EDECCipherException if this is
    ///   called for a cipher mode not supporting authentication.
    /// </returns>
    /// <exception cref="EDECCipherException">
    ///   Exception raised if called for a cipher mode not supporting
    ///   authentication.
    /// </exception>
    function  GetDataToAuthenticate: TBytes;
    /// <summary>
    ///   Returns the length of the resulting authentication value if a
    ///   cipher mode which provides authentication support as well is used.
    /// </summary>
    /// <returns>
    ///   Length of the authentication result in bit. Raises an
    ///   EDECCipherException if this is called for a cipher mode not supporting
    ///   authentication.
    /// </returns>
    /// <exception cref="EDECCipherException">
    ///   Exception raised if called for a cipher mode not supporting
    ///   authentication.
    /// </exception>
    function  GetAuthenticationResultBitLength: Integer;
    /// <summary>
    ///   Returns the value calculated over the data to be authenticated if a
    ///   cipher mode which provides authentication support as well is used.
    ///   The value will be returned even if decryption resulted in a wrong value.
    ///   A wrong authentication result on decryption is signalled via exception.
    /// </summary>
    /// <returns>
    ///   Result of the authentication. Raises an EDECCipherException if this is
    ///   called for a cipher mode not supporting authentication.
    /// </returns>
    /// <exception cref="EDECCipherException">
    ///   Exception raised if called for a cipher mode not supporting
    ///   authentication.
    /// </exception>
    function  GetCalcAuthenticatonResult: TBytes;
    /// <summary>
    ///   Defines the data which shall get authenticated when using a cipher
    ///   mode which provides authentication support as well.
    /// </summary>
    /// <param name="Value">
    ///   Data to be authenticated. Raises an EDECCipherException if this is
    ///   called for a cipher mode not supporting authentication.
    /// </param>
    /// <exception cref="EDECCipherException">
    ///   Exception raised if called for a cipher mode not supporting
    ///   authentication.
    /// </exception>
    procedure SetDataToAuthenticate(const Value: TBytes);
    /// <summary>
    ///   Sets the length of the resulting authentication value if a
    ///   cipher mode which provides authentication support as well is used.
    /// </summary>
    /// <param name="Value">
    ///   Length of the authentication result in bit. Raises an
    ///   EDECCipherException if this is called for a cipher mode not supporting
    ///   authentication.
    /// </param>
    /// <exception cref="EDECCipherException">
    ///   Exception raised if called for a cipher mode not supporting
    ///   authentication.
    /// </exception>
    procedure SetAuthenticationResultBitLength(const Value: Integer);

    /// <summary>
    ///   Returns a list of authentication tag lengths explicitely specified by
    ///   the official specification of the standard.
    /// </summary>
    /// <returns>
    ///   List of bit lengths. If the cipher mode used is not an authenticated
    ///   one, the array will just contain a single value of 0.
    /// </returns>
    function GetStandardAuthenticationTagBitLengths:TStandardBitLengths;

    /// <summary>
    ///   Returns the value set as expected authenthication value for ciphers
    ///   providing authehtication features as well. Raises an
    ///   EDECCipherException if this is called for a cipher mode not supporting
    ///   authentication.
    /// </summary>
    /// <exception cref="EDECCipherException">
    ///   Exception raised if called for a cipher mode not supporting
    ///   authentication.
    /// </exception>
    function GetExpectedAuthenticationResult: TBytes;
    /// <summary>
    ///   Sets the value used as expected authenthication value when decrypting
    ///   and a cipher providing authehtication features is being used. Raises an
    ///   EDECCipherException if this is called for a cipher mode not supporting
    ///   authentication.
    /// </summary>
    /// <exception cref="EDECCipherException">
    ///   Exception raised if called for a cipher mode not supporting
    ///   authentication.
    /// </exception>
    procedure SetExpectedAuthenticationResult(const Value: TBytes);

    /// <summary>
    ///   Some block chaining modes have the ability to authenticate the message
    ///   in addition to encrypting it. This property contains the data which
    ///   shall be authenticated in parallel to the encryption.
    /// </summary>
    property DataToAuthenticate : TBytes
      read   GetDataToAuthenticate
      write  SetDataToAuthenticate;

    /// <summary>
    ///   Some block chaining modes have the ability to authenticate the message
    ///   in addition to encrypting it.
    ///   Represents the length of AuthenticatonValue in bit, values as per
    ///   specification are: 128, 120, 112, 104, or 96 bit. For certain applications,
    ///   they may be 64 or 32 as well, but the use of these two tag lengths
    ///   constrains the length of the input data and the lifetime of the key.
    /// </summary>
    property AuthenticationResultBitLength : Integer
      read   GetAuthenticationResultBitLength
      write  SetAuthenticationResultBitLength;
    /// <summary>
    ///   Some block chaining modes have the ability to authenticate the message
    ///   in addition to encrypting it. This property contains the generated
    ///   authentication tag. Raises an EDECCipherException if this is
    ///   called for a cipher mode not supporting authentication.
    /// </summary>
    /// <exception cref="EDECCipherException">
    ///   Exception raised if called for a cipher mode not supporting
    ///   authentication.
    /// </exception>
    property CalculatedAuthenticationResult  : TBytes
      read   GetCalcAuthenticatonResult;

    /// <summary>
    ///   Expected authentication tag value, will be compared with actual value
    ///   when decryption finished. Raises an EDECCipherException if this is
    ///   called for a cipher mode not supporting authentication.
    /// </summary>
    /// <exception cref="EDECCipherException">
    ///   Exception raised if called for a cipher mode not supporting
    ///   authentication.
    /// </exception>
    property ExpectedAuthenticationResult : TBytes
      read   GetExpectedAuthenticationResult
      write  SetExpectedAuthenticationResult;
  end;

implementation

end.
