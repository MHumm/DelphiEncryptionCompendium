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
unit DECCipherFormats;
{$INCLUDE DECOptions.inc}

interface


uses
  {$IFDEF FPC}
  SysUtils, Classes,
  {$ELSE}
  System.SysUtils, System.Classes,
  {$ENDIF}
  DECCipherBase, DECCipherModes, DECCipherPaddings,
  DECUtil, DECTypes, DECFormatBase, DECCipherInterface;

type
  /// <summary>
  ///   Class type of the cipher base class which adds the additional Calc
  ///   variants for additional data types.
  /// </summary>
  TDECFormattedCipherClass = class of TDECFormattedCipher;

  /// <summary>
  ///   Class in which the various encode/decode variants provided have been
  ///   moved in order to keep the base cipher class small and clean.
  /// </summary>
  TDECFormattedCipher = class(TDECCipherModes, IDECCipher)
  strict private
    /// <summary>
    ///   The static class assigned to this field via Init method or PaddingMode
    ///   property is being used to add or remove paddings in order to simplyfy
    ///   ading further padding shemes.
    /// </summary>
    FPaddingClass : TDECPaddingClass;

    /// <summary>
    ///   Encrypts or decrypts the data contained in a given stream
    /// </summary>
    /// <param name="Source">
    ///   Source stream containing the data to encrypt or to decrypt
    /// </param>
    /// <param name="Dest">
    ///   Destination stream, where the encrypted or decrypted data shall be put in
    /// </param>
    /// <param name="DataSize">
    ///   Number of bytes of Source to be encrypted or decrypted
    /// </param>
    /// <param name="CipherProc">
    ///   Callback which either encrypts or decrypts the stream, depending on
    ///   which one is being passed
    /// </param>
    /// <param name="OnProgress">
    ///   optional callback for reporting progress of the operation
    /// </param>
    /// <param name="IsEncode">
    ///   True for encoding, False for decoding
    /// </param>
    /// <exception cref="EDECCipherException">
    ///   Raised if the padding mode used is not implemented yet
    /// </exception>
    procedure DoEncodeDecodeStream(const Source, Dest: TStream; DataSize: Int64;
                                   const CipherProc: TDECCipherCodeEvent;
                                   const OnProgress: TDECProgressEvent;
                                   IsEncode: Boolean);
    /// <summary>
    ///   Encrypts or decrypts a file and stores the result in another file
    /// </summary>
    /// <param name="SourceFileName">
    ///   Path and name of the file to encrypt
    /// </param>
    /// <param name="DestFileName">
    ///   Path and name of the file the encrypted data shall be stored in
    /// </param>
    /// <param name="Proc">
    ///   This method does the actual encrypting or decrypting of the data.
    ///   Usually the Encode or Decode method is being passed here which is
    ///   declared in TDECCipherBase as virtual abstract method and
    ///   implemented in the individual cipher class inheriting from this one
    /// </param>
    /// <param name="OnProgress">
    ///   Optional event which can be passed to get information about the
    ///   progress of the encryption operation
    /// </param>
    /// <param name="IsEncode">
    ///   True for encoding, False for decoding
    /// </remark>
    procedure DoEncodeDecodeFile(const SourceFileName, DestFileName: string;
                                 const Proc: TDECCipherCodeEvent;
                                 const OnProgress: TDECProgressEvent;
                                 IsEncode: Boolean);
  strict protected
    /// <summary>
    ///   Assignes the right padding class to the class type field.
    /// </summary>
    procedure InitPaddingClass; override;
  public
    /// <summary>
    ///   Encrypts the contents of a given byte array
    /// </summary>
    /// <param name="Source">
    ///   Byte array with data to be encrypted. When block chaining mode ECBx
    ///   is used (not recommended!), the size of the data passed via this
    ///   parameter needs to be a multiple of the block size of the algorithm used,
    ///   otherwise a EDECCipherException exception will be raised!
    /// </param>
    /// <returns>
    ///   Byte array with encrypted data
    /// </returns>
    /// <exception cref="EDECCipherException">
    ///   Exception raised if the length of the data passed as <c>Source</c>
    ///   is not a multiple of the algorithm's block size.
    /// </exception>
    function EncodeBytes(const Source: TBytes): TBytes;

    /// <summary>
    ///   Decrypts the contents of a given byte array
    /// </summary>
    /// <param name="Source">
    ///   Byte array with data to be decrypted. When block chaining mode ECBx
    ///   is used (not recommended!), the size of the data passed via this
    ///   parameter needs to be a multiple of the block size of the algorithm used,
    ///   otherwise a EDECCipherException exception will be raised!
    /// </param>
    /// <returns>
    ///   Byte array with decrypted data
    /// </returns>
    /// <exception cref="EDECCipherException">
    ///   Exception raised if the length of the data passed as <c>Source</c>
    ///   is not a multiple of the algorithm's block size.
    /// </exception>
    function DecodeBytes(const Source: TBytes): TBytes;

    /// <summary>
    ///   Encrypts the data contained in a given stream
    /// </summary>
    /// <param name="Source">
    ///   Source stream containing the data to encrypt. When block chaining mode ECBx
    ///   is used (not recommended!), the size of the data passed via this
    ///   parameter needs to be a multiple of the block size of the algorithm used,
    ///   otherwise a EDECCipherException exception will be raised!
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
    /// <exception cref="EDECCipherException">
    ///   Exception raised if the length of the data passed as <c>Source</c>
    ///   is not a multiple of the algorithm's block size.
    /// </exception>
    procedure EncodeStream(const Source, Dest: TStream; DataSize: Int64;
                           const OnProgress: TDECProgressEvent = nil);

    /// <summary>
    ///   Decrypts the data contained in a given stream
    /// </summary>
    /// <param name="Source">
    ///   Source stream containing the data to decrypt. When block chaining mode ECBx
    ///   is used (not recommended!), the size of the data passed via this
    ///   parameter needs to be a multiple of the block size of the algorithm used,
    ///   otherwise a EDECCipherException exception will be raised!
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
    /// <exception cref="EDECCipherException">
    ///   Exception raised if the length of the data passed as <c>Source</c>
    ///   is not a multiple of the algorithm's block size.
    /// </exception>
    procedure DecodeStream(const Source, Dest: TStream; DataSize: Int64;
                           const OnProgress: TDECProgressEvent = nil);

    /// <summary>
    ///   Reads the contents of one file, encrypts it and stores it in another file
    /// </summary>
    /// <param name="SourceFileName">
    ///   Path and name of the file to encrypt. When block chaining mode ECBx
    ///   is used (not recommended!), the size of the data passed via this
    ///   parameter needs to be a multiple of the block size of the algorithm
    ///   used, otherwise a EDECCipherException exception will be raised!
    /// </param>
    /// <param name="DestFileName">
    ///   Path and name of the file the encrypted data shall be stored in
    /// </param>
    /// <param name="OnProgress">
    ///   Optional event which can be passed to get information about the
    ///   progress of the encryption operation
    /// </param>
    /// <exception cref="EDECCipherException">
    ///   Exception raised if the length of the data passed as <c>Source</c>
    ///   is not a multiple of the algorithm's block size.
    /// </exception>
    procedure EncodeFile(const SourceFileName, DestFileName: string;
                         const OnProgress: TDECProgressEvent = nil);

    /// <summary>
    ///   Reads the contents of one file, decrypts it and stores it in another file
    /// </summary>
    /// <param name="SourceFileName">
    ///   Path and name of the file to decrypt. When block chaining mode ECBx
    ///   is used (not recommended!), the size of the data passed via this
    ///   parameter needs to be a multiple of the block size of the algorithm
    ///   used, otherwise a EDECCipherException exception will be raised!
    /// </param>
    /// <param name="DestFileName">
    ///   Path and name of the file the decrypted data shall be stored in
    /// </param>
    /// <param name="OnProgress">
    ///   Optional event which can be passed to get information about the
    ///   progress of the decryption operation
    /// </param>
    /// <exception cref="EDECCipherException">
    ///   Exception raised if the length of the data passed as <c>Source</c>
    ///   is not a multiple of the algorithm's block size.
    /// </exception>
    procedure DecodeFile(const SourceFileName, DestFileName: string;
                         const OnProgress: TDECProgressEvent = nil);

    /// <summary>
    ///   Encrypts the contents of the passed unicode string
    /// </summary>
    /// <param name="Source">
    ///   String to encrypt. When block chaining mode ECBx
    ///   is used (not recommended!), the size of the data passed via this
    ///   parameter needs to be a multiple of the block size of the algorithm
    ///   used, otherwise a EDECCipherException exception will be raised!
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
    /// <exception cref="EDECCipherException">
    ///   Exception raised if the length of the data passed as <c>Source</c>
    ///   is not a multiple of the algorithm's block size.
    /// </exception>
    function EncodeStringToBytes(const Source: string;
                                 Format: TDECFormatClass = nil): TBytes; overload;

    /// <summary>
    ///   Encrypts the contents of the passed RawByteString
    /// </summary>
    /// <param name="Source">
    ///   String to encrypt. When block chaining mode ECBx
    ///   is used (not recommended!), the size of the data passed via this
    ///   parameter needs to be a multiple of the block size of the algorithm
    ///   used, otherwise a EDECCipherException exception will be raised!
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
    /// <exception cref="EDECCipherException">
    ///   Exception raised if the length of the data passed as <c>Source</c>
    ///   is not a multiple of the algorithm's block size.
    /// </exception>
    function EncodeStringToBytes(const Source: RawByteString;
                                 Format: TDECFormatClass = nil): TBytes; overload;

    /// <summary>
    ///   Encrypts the contents of the passed unicode string
    /// </summary>
    /// <param name="Source">
    ///   String to encrypt. When block chaining mode ECBx
    ///   is used (not recommended!), the size of the data passed via this
    ///   parameter needs to be a multiple of the block size of the algorithm
    ///   used, otherwise a EDECCipherException exception will be raised!
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
    /// <exception cref="EDECCipherException">
    ///   Exception raised if the length of the data passed as <c>Source</c>
    ///   is not a multiple of the algorithm's block size.
    /// </exception>
    function EncodeStringToString(const Source: string;
                                  Format: TDECFormatClass = nil): string; overload;

    /// <summary>
    ///   Encrypts the contents of the passed unicode string
    /// </summary>
    /// <param name="Source">
    ///   String to encrypt. When block chaining mode ECBx
    ///   is used (not recommended!), the size of the data passed via this
    ///   parameter needs to be a multiple of the block size of the algorithm
    ///   used, otherwise a EDECCipherException exception will be raised!
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
    /// <exception cref="EDECCipherException">
    ///   Exception raised if the length of the data passed as <c>Source</c>
    ///   is not a multiple of the algorithm's block size.
    /// </exception>
    function EncodeStringToString(const Source: RawByteString;
                                  Format: TDECFormatClass = nil): RawByteString; overload;

    /// <summary>
    ///   Decrypts the contents of the passed encrypted unicode string
    /// </summary>
    /// <param name="Source">
    ///   String to decrypt. When block chaining mode ECBx
    ///   is used (not recommended!), the size of the data passed via this
    ///   parameter needs to be a multiple of the block size of the algorithm
    ///   used, otherwise a EDECCipherException exception will be raised!
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
    /// <exception cref="EDECCipherException">
    ///   Exception raised if the length of the data passed as <c>Source</c>
    ///   is not a multiple of the algorithm's block size.
    /// </exception>
    function DecodeStringToBytes(const Source: string;
                                 Format: TDECFormatClass = nil): TBytes; overload;

    /// <summary>
    ///   Decrypts the contents of the passed encrypted RawByteString
    /// </summary>
    /// <param name="Source">
    ///   String to decrypt. When block chaining mode ECBx
    ///   is used (not recommended!), the size of the data passed via this
    ///   parameter needs to be a multiple of the block size of the algorithm
    ///   used, otherwise a EDECCipherException exception will be raised!
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
    /// <exception cref="EDECCipherException">
    ///   Exception raised if the length of the data passed as <c>Source</c>
    ///   is not a multiple of the algorithm's block size.
    /// </exception>
    function DecodeStringToBytes(const Source: RawByteString;
                                 Format: TDECFormatClass = nil): TBytes; overload;

    /// <summary>
    ///   Decrypts the contents of the passed Unicode string
    /// </summary>
    /// <param name="Source">
    ///   String to decrypt. When block chaining mode ECBx
    ///   is used (not recommended!), the size of the data passed via this
    ///   parameter needs to be a multiple of the block size of the algorithm
    ///   used, otherwise a EDECCipherException exception will be raised!
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
    /// <exception cref="EDECCipherException">
    ///   Exception raised if the length of the data passed as <c>Source</c>
    ///   is not a multiple of the algorithm's block size.
    /// </exception>
    function DecodeStringToString(const Source: string;
                                  Format: TDECFormatClass = nil): string; overload;

    /// <summary>
    ///   Decrypts the contents of the passed RawByteString string
    /// </summary>
    /// <param name="Source">
    ///   String to decrypt. When block chaining mode ECBx
    ///   is used (not recommended!), the size of the data passed via this
    ///   parameter needs to be a multiple of the block size of the algorithm
    ///   used, otherwise a EDECCipherException exception will be raised!
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
    /// <exception cref="EDECCipherException">
    ///   Exception raised if the length of the data passed as <c>Source</c>
    ///   is not a multiple of the algorithm's block size.
    /// </exception>
    function DecodeStringToString(const Source: RawByteString;
                                  Format: TDECFormatClass = nil): RawByteString; overload;

{$IFDEF ANSISTRINGSUPPORTED}
    /// <summary>
    ///   Encrypts the contents of the passed Ansistring
    /// </summary>
    /// <param name="Source">
    ///   String to encrypt. When block chaining mode ECBx
    ///   is used (not recommended!), the size of the data passed via this
    ///   parameter needs to be a multiple of the block size of the algorithm
    ///   used, otherwise a EDECCipherException exception will be raised!
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
    /// <exception cref="EDECCipherException">
    ///   Exception raised if the length of the data passed as <c>Source</c>
    ///   is not a multiple of the algorithm's block size.
    /// </exception>
    function EncodeStringToBytes(const Source: AnsiString;
                                 Format: TDECFormatClass = nil): TBytes; overload;

    /// <summary>
    ///   Encrypts the contents of the passed Ansistring
    /// </summary>
    /// <param name="Source">
    ///   String to encrypt. When block chaining mode ECBx
    ///   is used (not recommended!), the size of the data passed via this
    ///   parameter needs to be a multiple of the block size of the algorithm
    ///   used, otherwise a EDECCipherException exception will be raised!
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
    /// <exception cref="EDECCipherException">
    ///   Exception raised if the length of the data passed as <c>Source</c>
    ///   is not a multiple of the algorithm's block size.
    /// </exception>
    function EncodeStringToString(const Source: AnsiString;
                                  Format: TDECFormatClass = nil): AnsiString; overload;

    /// <summary>
    ///   Decrypts the contents of the passed encrypted Ansistring
    /// </summary>
    /// <param name="Source">
    ///   String to decrypt. When block chaining mode ECBx
    ///   is used (not recommended!), the size of the data passed via this
    ///   parameter needs to be a multiple of the block size of the algorithm
    ///   used, otherwise a EDECCipherException exception will be raised!
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
    /// <exception cref="EDECCipherException">
    ///   Exception raised if the length of the data passed as <c>Source</c>
    ///   is not a multiple of the algorithm's block size.
    /// </exception>
    function DecodeStringToBytes(const Source: AnsiString;
                                 Format: TDECFormatClass = nil): TBytes; overload;

    /// <summary>
    ///   Decrypts the contents of the passed AnsiString string
    /// </summary>
    /// <param name="Source">
    ///   String to decrypt. When block chaining mode ECBx
    ///   is used (not recommended!), the size of the data passed via this
    ///   parameter needs to be a multiple of the block size of the algorithm
    ///   used, otherwise a EDECCipherException exception will be raised!
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
    /// <exception cref="EDECCipherException">
    ///   Exception raised if the length of the data passed as <c>Source</c>
    ///   is not a multiple of the algorithm's block size.
    /// </exception>
    function DecodeStringToString(const Source: AnsiString;
                                  Format: TDECFormatClass = nil): AnsiString; overload;
{$ENDIF}

{$IFNDEF NEXTGEN}
    /// <summary>
    ///   Encrypts the contents of the passed Widestring
    /// </summary>
    /// <param name="Source">
    ///   String to encrypt. When block chaining mode ECBx
    ///   is used (not recommended!), the size of the data passed via this
    ///   parameter needs to be a multiple of the block size of the algorithm
    ///   used, otherwise a EDECCipherException exception will be raised!
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
    /// <exception cref="EDECCipherException">
    ///   Exception raised if the length of the data passed as <c>Source</c>
    ///   is not a multiple of the algorithm's block size.
    /// </exception>
    function EncodeStringToBytes(const Source: WideString;
                                 Format: TDECFormatClass = nil): TBytes; overload;

    /// <summary>
    ///   Encrypts the contents of the passed Widestring
    /// </summary>
    /// <param name="Source">
    ///   String to encrypt. When block chaining mode ECBx
    ///   is used (not recommended!), the size of the data passed via this
    ///   parameter needs to be a multiple of the block size of the algorithm
    ///   used, otherwise a EDECCipherException exception will be raised!
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
    /// <exception cref="EDECCipherException">
    ///   Exception raised if the length of the data passed as <c>Source</c>
    ///   is not a multiple of the algorithm's block size.
    /// </exception>
    function EncodeStringToString(const Source: WideString;
                                  Format: TDECFormatClass = nil): WideString; overload;

    /// <summary>
    ///   Decrypts the contents of the passed encrypted Widestring
    /// </summary>
    /// <param name="Source">
    ///   String to decrypt. When block chaining mode ECBx
    ///   is used (not recommended!), the size of the data passed via this
    ///   parameter needs to be a multiple of the block size of the algorithm
    ///   used, otherwise a EDECCipherException exception will be raised!
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
    /// <exception cref="EDECCipherException">
    ///   Exception raised if the length of the data passed as <c>Source</c>
    ///   is not a multiple of the algorithm's block size.
    /// </exception>
    function DecodeStringToBytes(const Source: WideString;
                                 Format: TDECFormatClass = nil): TBytes; overload;

    /// <summary>
    ///   Decrypts the contents of the passed WideString string
    /// </summary>
    /// <param name="Source">
    ///   String to decrypt. When block chaining mode ECBx
    ///   is used (not recommended!), the size of the data passed via this
    ///   parameter needs to be a multiple of the block size of the algorithm
    ///   used, otherwise a EDECCipherException exception will be raised!
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
    /// <exception cref="EDECCipherException">
    ///   Exception raised if the length of the data passed as <c>Source</c>
    ///   is not a multiple of the algorithm's block size.
    /// </exception>
    function DecodeStringToString(const Source: WideString;
                                  Format: TDECFormatClass = nil): WideString; overload;
{$ENDIF}
  end;

implementation

uses
  {$IFDEF FPC}
  TypInfo,
  {$ELSE}
  System.TypInfo,
  {$ENDIF}
  DECBaseClass;

resourcestring
  sPaddingModeNotImplemented = 'Padding mode %0:s not implemented';

function TDECFormattedCipher.EncodeBytes(const Source: TBytes): TBytes;

  function CipherEncodeBytes(const Source: TBytes): TBytes;
  begin
    SetLength(Result, Length(Source));
    if Length(Result) > 0 then
      Encode(Source[0], Result[0], Length(Source))
    else
      if (FMode = cmGCM) then
        EncodeGCM(@Source, @Result, 0);
  end;

begin
  if not (FPaddingClass = nil) then
    Result := CipherEncodeBytes(FPaddingClass.AddPadding(Source, Context.BlockSize))
  else
    Result := CipherEncodeBytes(Source);
end;

function TDECFormattedCipher.DecodeBytes(const Source: TBytes): TBytes;
begin
  Result := Source;

  if Length(Result) > 0 then
  begin
    if (FMode = cmGCM) then
      SetLength(Result, Length(Source));

    Decode(Source[0], Result[0], Length(Source));
  end
  else
    if (FMode = cmGCM) then
      DecodeGCM(@Source, @Result, 0);

  if not (FPaddingClass = nil) then
    Result := FPaddingClass.RemovePadding(Result, Context.BlockSize);
end;

procedure TDECFormattedCipher.DoEncodeDecodeStream(const Source, Dest: TStream;
                                                   DataSize: Int64;
                                                   const CipherProc: TDECCipherCodeEvent;
                                                   const OnProgress: TDECProgressEvent;
                                                   IsEncode: Boolean);
var
  Buffer             : TBytes;
  outBuffer          : TBytes;
  BufferSize, Bytes  : Integer;
  Max, StartPos, Pos : Int64;
  doPadding,
  doAdjustBuffer,
  doStartOnlyPadding : Boolean;
begin
  Pos := Source.Position;
  if DataSize < 0 then
    DataSize := Source.Size - Pos;

  Max       := Pos + DataSize;
  StartPos  := Pos;
  doPadding := false;
  doStartOnlyPadding := (DataSize = 0) and IsEncode and
    (FPaddingMode <> pmNone);

  if (DataSize > 0) or doStartOnlyPadding then
  begin
    try
      if Assigned(OnProgress) then
        OnProgress(Max, 0, Started);

      if StreamBufferSize <= 0 then
        StreamBufferSize := 8192;
      BufferSize := StreamBufferSize mod Context.BlockSize;
      if BufferSize = 0 then
        BufferSize := StreamBufferSize
      else
        BufferSize := StreamBufferSize + Context.BlockSize - BufferSize;
      if DataSize > BufferSize then
        SetLength(Buffer, BufferSize)
      else
        SetLength(Buffer, DataSize);

      outBuffer := Buffer;
      if (FMode = cmGCM) then
        SetLength(outBuffer, Length(Buffer));

      while (DataSize > 0) or doStartOnlyPadding do
      begin
        doStartOnlyPadding := false;
        Bytes := BufferSize;
        if Bytes >= DataSize then
        begin
          doAdjustBuffer := Bytes > DataSize;
          Bytes := DataSize;
          // Handle padding mode
          doPadding := (FPaddingMode <> pmNone) and assigned(FPaddingCLass);
          if doPadding and doAdjustBuffer then
            if IsEncode then
            begin
              ProtectBytes(Buffer);
              SetLength(Buffer, Bytes);
            end
            else
            begin
              ProtectBytes(outBuffer);
              SetLength(outBuffer, Bytes);
            end;
        end;

        if Bytes > 0 then
          Source.ReadBuffer(Buffer[0], Bytes);

        if IsEncode and doPadding then
        begin
          Buffer := FPaddingClass.AddPadding(Buffer, Context.BlockSize);
          Bytes  := length(Buffer);
          SetLength(outBuffer, length(Buffer));
        end;

        // The real encryption or decryption routine
        CipherProc(Buffer[0], outBuffer[0], Bytes);
        if not IsEncode and doPadding then
        begin
          outBuffer := FPaddingCLass.RemovePadding(outBuffer, Context.BlockSize);
          Bytes := length(outBuffer);
        end;
        if Bytes > 0 then
          Dest.WriteBuffer(outBuffer[0], Bytes)
        else
          SetLength(outBuffer, 0);
        if doPadding then
        begin
          DataSize := 0;
          Pos := Max;
        end else begin
          Dec(DataSize, Bytes);
          Inc(Pos, Bytes);
        end;
        if Assigned(OnProgress) then
          OnProgress(Max, Pos - StartPos, Processing);
      end;
    finally
      ProtectBytes(Buffer);
      ProtectBytes(outBuffer);
      if Assigned(OnProgress) then
        OnProgress(Max, Max, Finished);
    end;
  end
  else
    if (FMode = cmGCM) then
    begin
      Buffer := nil;
      CipherProc(Buffer, Buffer, 0);
    end;
end;

procedure TDECFormattedCipher.EncodeStream(const Source, Dest: TStream; DataSize: Int64;
                                           const OnProgress: TDECProgressEvent);
begin
  DoEncodeDecodeStream(Source, Dest, DataSize, Encode, OnProgress, true);
end;

procedure TDECFormattedCipher.DecodeStream(const Source, Dest: TStream; DataSize: Int64;
                                           const OnProgress: TDECProgressEvent);
begin
  DoEncodeDecodeStream(Source, Dest, DataSize, Decode, OnProgress, false);
end;

procedure TDECFormattedCipher.DoEncodeDecodeFile(const SourceFileName, DestFileName: string;
                                                 const Proc: TDECCipherCodeEvent;
                                                 const OnProgress: TDECProgressEvent;
                                                 IsEncode: Boolean);
var
  S, D: TStream;
begin
  Assert(SourceFileName <> DestFileName, 'Source and Dest file name may not be equal');

  S := TFileStream.Create(SourceFileName, fmOpenRead or fmShareDenyNone);
  try
    D := TFileStream.Create(DestFileName, fmCreate);
    try
      DoEncodeDecodeStream(S, D, S.Size, Proc, OnProgress, IsEncode);
    finally
      D.Free;
    end;
  finally
    S.Free;
  end;
end;

procedure TDECFormattedCipher.EncodeFile(const SourceFileName, DestFileName: string;
                                         const OnProgress: TDECProgressEvent);
begin
  DoEncodeDecodeFile(SourceFileName, DestFileName, Encode, OnProgress, true);
end;

procedure TDECFormattedCipher.DecodeFile(const SourceFileName, DestFileName: string;
                                         const OnProgress: TDECProgressEvent);
begin
  DoEncodeDecodeFile(SourceFileName, DestFileName, Decode, OnProgress, false);
end;

function TDECFormattedCipher.EncodeStringToBytes(const Source: string;
                                                 Format: TDECFormatClass = nil): TBytes;
  function CipherEncodeStringToBytes(const Source: string;
    Format: TDECFormatClass): TBytes;
  var
    Len: Integer;
  begin
    {$IFDEF HAVE_STR_LIKE_ARRAY}
    Len := Length(Source) * SizeOf(Source[low(Source)]);
    SetLength(Result, Len);
    Encode(Source[low(Source)], Result[0], Len);
    {$ELSE}
    Len := Length(Source) * SizeOf(Source[1]);
    SetLength(Result, Len);
    Encode(Source[1], Result[0], Len);
    {$ENDIF}
  end;

begin
  if not (FPaddingCLass = nil) then
    Result := CipherEncodeStringToBytes(FPaddingClass.AddPadding(Source, Context.BlockSize),
                                        Format)
  else
    if Length(Source) > 0 then
      Result := CipherEncodeStringToBytes(Source, Format)
    else
    begin
      SetLength(Result, 0);
      exit;
    end;

  Result := ValidFormat(Format).Encode(Result);
end;

function TDECFormattedCipher.EncodeStringToBytes(const Source : RawByteString;
                                                 Format       : TDECFormatClass): TBytes;

  function CipherEncodeStringToBytes(const Source: RawByteString;
    Format: TDECFormatClass): TBytes;
  var
    Len: Integer;
  begin
    {$IFDEF HAVE_STR_LIKE_ARRAY}
    Len := Length(Source) * SizeOf(Source[low(Source)]);
    SetLength(Result, Len);
    Encode(Source[low(Source)], Result[0], Len);
    {$ELSE}
    Len := Length(Source) * SizeOf(Source[1]);
    SetLength(Result, Len);
    Encode(Source[1], Result[0], Len);
    {$ENDIF}
  end;

begin
  if not (FPaddingCLass = nil) then
    Result := CipherEncodeStringToBytes(FPaddingClass.AddPadding(Source, Context.BlockSize),
                                        Format)
    else
      if Length(Source) > 0 then
        Result := CipherEncodeStringToBytes(Source, Format)
      else
      begin
        SetLength(Result, 0);
        exit;
      end;

  Result := ValidFormat(Format).Encode(Result);
end;

function TDECFormattedCipher.DecodeStringToBytes(const Source: string; Format: TDECFormatClass): TBytes;
var
  Len: Integer;
  Src: TBytes;
begin
  if Length(Source) > 0 then
  begin
    Src := ValidFormat(Format).Decode(BytesOf(Source));

    Len := Length(Src);
    Result := Src;
    Decode(Result[0], Result[0], Len);
  end
  else
    SetLength(Result, 0);

  if not (FPaddingCLass = nil) then
    Result := FPaddingClass.RemovePadding(Result, Context.BlockSize);
end;

function TDECFormattedCipher.DecodeStringToBytes(const Source: RawByteString; Format: TDECFormatClass): TBytes;
var
  Len: Integer;
  Src: TBytes;
begin
  if Length(Source) > 0 then
  begin
    Src := ValidFormat(Format).Decode(BytesOf(Source));

    Len := Length(Src);
    Result := Src;
    Decode(Result[0], Result[0], Len);
  end
  else
    SetLength(Result, 0);

  if not (FPaddingCLass = nil) then
    Result := FPaddingClass.RemovePadding(Result, Context.BlockSize);
end;

{$IFDEF ANSISTRINGSUPPORTED}
function TDECFormattedCipher.EncodeStringToBytes(const Source: AnsiString; Format: TDECFormatClass): TBytes;

  function CipherEncodeStringToBytes(const Source: AnsiString;
    Format: TDECFormatClass): TBytes;
  var
    Len: Integer;
  begin
    Len := Length(Source) * SizeOf(Source[1]);
    SetLength(Result, Len);
    Encode(Source[1], Result[0], Len);
  end;

begin
  if not (FPaddingCLass = nil) then
    Result := CipherEncodeStringToBytes(FPaddingClass.AddPadding(Source, Context.BlockSize),
                                        Format);
  else
    if Length(Source) > 0 then
      Result := CipherEncodeStringToBytes(Source, Format)
    else
    begin
      SetLength(Result, 0);
      exit;
    end;

  Result := ValidFormat(Format).Encode(Result);
end;
{$ENDIF}

{$IFDEF ANSISTRINGSUPPORTED}
function TDECFormattedCipher.DecodeStringToBytes(const Source: AnsiString; Format: TDECFormatClass): TBytes;
var
  Len: Integer;
  Src: TBytes;
begin
  if Length(Source) > 0 then
  begin
    Src := ValidFormat(Format).Decode(SysUtils.BytesOf(Source));

    Len := Length(Src);
    SetLength(Result, Len);
    Decode(Src[0], Result[0], Len);
  end
  else
    SetLength(Result, 0);

  if not (FPaddingCLass = nil) then
    Result := FPaddingClass.RemovePadding(Result, Context.BlockSize);
end;
{$ENDIF}

{$IFNDEF NEXTGEN}
function TDECFormattedCipher.EncodeStringToBytes(const Source: WideString; Format: TDECFormatClass): TBytes;

  function CipherEncodeStringToBytes(const Source: WideString;
    Format: TDECFormatClass): TBytes;
  var
    Len: Integer;
  begin
    Len := Length(Source) * SizeOf(Source[1]);
    SetLength(Result, Len);
    Encode(Source[1], Result[0], Len);
  end;

begin
  if not (FPaddingCLass = nil) then
    Result := CipherEncodeStringToBytes(FPaddingClass.AddPadding(Source, Context.BlockSize),
                                        Format)
  else
    if Length(Source) > 0 then
      Result := CipherEncodeStringToBytes(Source, Format)
    else
    begin
      SetLength(Result, 0);
      exit;
    end;

  Result := ValidFormat(Format).Encode(Result);
end;

function TDECFormattedCipher.EncodeStringToString(const Source: WideString;
  Format: TDECFormatClass): WideString;
begin
  result := WideString(EncodeStringToString(string(Source), Format));
end;

procedure TDECFormattedCipher.InitPaddingClass;
begin
  case FPaddingMode of
    pmNone       : FPaddingClass := nil;
    pmPKCS7      : FPaddingCLass := TPKCS7Padding;
    pmPKCS5      : FPaddingCLass := TPKCS5Padding;
    pmANSI_X9_23 : FPaddingCLass := TANSI_X9_23_Padding;
    pmISO10126   : FPaddingCLass := TISO10126Padding;
    pmISO7816    : FPaddingCLass := TISO7816Padding;
    else
      raise EDECCipherException.CreateResFmt(@sPaddingModeNotImplemented,
                                             [GetEnumName(TypeInfo(TPaddingMode),
                                                Integer(FPaddingMode))]);
  end;
end;

{$ENDIF}

{$IFDEF ANSISTRINGSUPPORTED}
function TDECFormattedCipher.EncodeStringToString(const Source: AnsiString;
  Format: TDECFormatClass): AnsiString;

    function CipherEncodeStringToBytes(const Source: AnsiString;
      Format: TDECFormatClass): TBytes;
    var
      Len: Integer;
    begin
      Len := Length(Source) * SizeOf(Source[1]);
      SetLength(Result, Len);
      Encode(Source[1], Result[0], Len);
    end;

var
  EncryptedBuffer : TBytes;
  Temp            : TBytes;
begin
  if not (FPaddingClass = nil) then
    EncryptedBuffer := CipherEncodeStringToBytes(
                         TPaddingClass.AddPadding(Source, Context.BlockSize), Format)
  else
    if Length(Source) > 0 then
      EncryptedBuffer := CipherEncodeStringToBytes(Source)
    else
      exit('');

  Temp := ValidFormat(Format).Encode(EncryptedBuffer);
  SetLength(Result, length(Temp));
  Move(Temp[0], Result[1], length(Temp));
end;
{$ENDIF}

function TDECFormattedCipher.EncodeStringToString(const Source: string;
  Format: TDECFormatClass): string;

  function CipherEncodeStringToBytes(const Source: string;
    Format: TDECFormatClass): TBytes;
  var
    SourceSize: Integer;
  begin
    {$IFDEF HAVE_STR_LIKE_ARRAY}
    SourceSize := Length(Source) * SizeOf(Source[low(Source)]);
    SetLength(Result, SourceSize);
    Encode(Source[low(Source)], Result[0], SourceSize);
    {$ELSE}
    SourceSize := Length(Source) * SizeOf(Source[1]);
    SetLength(Result, SourceSize);
    Encode(Source[1], Result[0], SourceSize);
    {$ENDIF}
  end;

var
  EncryptedBuffer : TBytes;
begin
  if not (FPaddingClass = nil) then
    EncryptedBuffer := CipherEncodeStringToBytes(
                         FPaddingClass.AddPadding(Source, Context.BlockSize),
                                                  Format)
  else
    if Length(Source) > 0 then
      EncryptedBuffer := CipherEncodeStringToBytes(Source, Format)
    else
      exit('');

  Result := StringOf(ValidFormat(Format).Encode(EncryptedBuffer));
end;

function TDECFormattedCipher.EncodeStringToString(const Source: RawByteString;
  Format: TDECFormatClass): RawByteString;

  function CipherEncodeStringToBytes(const Source: RawByteString;
    Format: TDECFormatClass): TBytes;
  var
    SourceSize: Integer;
  begin
    {$IFDEF HAVE_STR_LIKE_ARRAY}
    SourceSize := Length(Source) * SizeOf(Source[low(Source)]);
    SetLength(Result, SourceSize);
    Encode(Source[low(Source)], Result[0], SourceSize);
    {$ELSE}
    SourceSize := Length(Source) * SizeOf(Source[1]);
    SetLength(Result, SourceSize);
    Encode(Source[1], Result[0], SourceSize);
    {$ENDIF}
  end;

var
  EncryptedBuffer : TBytes;
  Temp            : TBytes;
begin
  if not (FPaddingClass = nil) then
    EncryptedBuffer := CipherEncodeStringToBytes(
                         FPaddingClass.AddPadding(Source, Context.BlockSize),
                                                  Format)
  else
    if Length(Source) > 0 then
      EncryptedBuffer := CipherEncodeStringToBytes(Source, Format)
    else
      exit('');

  Temp := ValidFormat(Format).Encode(EncryptedBuffer);
  SetLength(Result, length(Temp));
  {$IFDEF HAVE_STR_LIKE_ARRAY}
  Move(Temp[0], Result[low(Result)], length(Temp))
  {$ELSE}
  Move(Temp[0], Result[1], length(Temp))
  {$ENDIF}
end;

{$IFNDEF NEXTGEN}
function TDECFormattedCipher.DecodeStringToBytes(const Source: WideString; Format: TDECFormatClass): TBytes;
var
  Len: Integer;
  Src: TBytes;
begin
  if Length(Source) > 0 then
  begin
    Src := ValidFormat(Format).Decode(BytesOf(Source));

    Len := Length(Src);
    SetLength(Result, Len);
    Decode(Src[0], Result[0], Len);
  end
  else
    SetLength(Result, 0);

  if not (FPaddingClass = nil) then
    Result := FPaddingClass.RemovePadding(Result, Context.BlockSize);
end;
{$ENDIF}

{$IFDEF ANSISTRINGSUPPORTED}
function TDECFormattedCipher.DecodeStringToString(const Source: AnsiString;
  Format: TDECFormatClass): AnsiString;
var
  Len : Integer;
  Src : TBytes;
  Tmp : TBytes;
begin
  if Length(Source) > 0 then
  begin
    Src := ValidFormat(Format).Decode(SysUtils.BytesOf(Source));

    Len := Length(Src);
    SetLength(Tmp, Len);
    Decode(Src[0], Tmp[0], Len);

    SetLength(Result, length(Tmp));

    {$IFDEF HAVE_STR_LIKE_ARRAY}
    Move(Tmp[0], Result[low(Result)], length(Tmp))
    {$ELSE}
    Move(Tmp[0], Result[1], length(Tmp))
    {$ENDIF}
  end
  else
    SetLength(Result, 0);

  if not (FPaddingClass = nil) then
    Result := FPaddingClass.RemovePadding(Result, Context.BlockSize);
end;
{$ENDIF}

{$IFNDEF NEXTGEN}
function TDECFormattedCipher.DecodeStringToString(const Source: WideString;
  Format: TDECFormatClass): WideString;
begin
  Result := WideString(DecodeStringToString(string(Source), Format));
end;
{$ENDIF}

function TDECFormattedCipher.DecodeStringToString(const Source: RawByteString;
  Format: TDECFormatClass): RawByteString;
var
  Len : Integer;
  Src : TBytes;
  Tmp : TBytes;
begin
  if Length(Source) > 0 then
  begin
    Src := ValidFormat(Format).Decode(BytesOf(Source));

    Len := Length(Src);
    SetLength(Tmp, Len);
    Decode(Src[0], Tmp[0], Len);

    SetLength(Result, length(Tmp));

    {$IFDEF HAVE_STR_LIKE_ARRAY}
    Move(Tmp[0], Result[low(Result)], length(Tmp))
    {$ELSE}
    Move(Tmp[0], Result[1], length(Tmp))
    {$ENDIF}
  end
  else
    SetLength(Result, 0);

  if not (FPaddingClass = nil) then
    Result := FPaddingClass.RemovePadding(Result, Context.BlockSize);
end;

function TDECFormattedCipher.DecodeStringToString(const Source: string;
  Format: TDECFormatClass): string;
var
  Len : Integer;
  Src : TBytes;
  Tmp : TBytes;
begin
  if Length(Source) > 0 then
  begin
    Src := ValidFormat(Format).Decode(BytesOf(Source));

    Len := Length(Src);
    SetLength(Tmp, Len);
    Decode(Src[0], Tmp[0], Len);
    Result := WideStringOf(Tmp);
  end
  else
    SetLength(Result, 0);

  if not (FPaddingClass = nil) then
    Result := FPaddingClass.RemovePadding(Result, Context.BlockSize);
end;

end.
