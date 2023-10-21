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
unit DECHashInterface;
{$INCLUDE DECOptions.inc}

interface

uses
  {$IFDEF FPC}
  SysUtils, Classes,
  {$ELSE}
  System.SysUtils, System.Classes,
  {$ENDIF}
  DECFormat, DECTypes;

type
  /// <summary>
  ///   Generic interface for all hash classes.
  ///   Unfortunately without all the class methods, as they are not accepted
  ///   in interface declarations
  /// </summary>
  IDECHash = Interface
  ['{4AF2CD8C-5438-4E8C-B4EA-D6DAD09642C5}']
    /// <summary>
    ///   Generic initialization of internal data structures. Additionally the
    ///   internal algorithm specific (because of being overridden by each
    ///   hash algorithm) DoInit method. Needs to be called before each hash
    ///   calculation.
    /// </summary>
    procedure Init;
    /// <summary>
    ///   Calculates one chunk of data to be hashed.
    /// </summary>
    /// <param name="Data">
    ///   Data on which the hash value shall be calculated on
    /// </param>
    /// <param name="DataSize">
    ///   Size of the data in bytes
    /// </param>
    procedure Calc(const Data; DataSize: Integer);

    /// <summary>
    ///   Frees dynamically allocated buffers in a way which safeguards agains
    ///   data stealing by other methods which afterwards might allocate this memory.
    ///   Additionaly calls the algorithm spercific DoDone method.
    /// </summary>
    procedure Done;

    /// <summary>
    ///   Returns the calculated hash value as byte array
    /// </summary>
    function DigestAsBytes: TBytes;

    /// <summary>
    ///   Returns the calculated hash value as formatted Unicode string
    /// </summary>
    /// <param name="Format">
    ///   Optional parameter. If a formatting class is being passed the formatting
    ///   will be applied to the returned string. Otherwise no formatting is
    ///   being used.
    /// </param>
    /// <returns>
    ///   Hash value of the last performed hash calculation
    /// </returns>
    /// <remarks>
    ///   We recommend to use a formatting which results in 7 bit ASCII chars
    ///   being returned, otherwise the conversion into the Unicode string might
    ///   result in strange characters in the returned result.
    /// </remarks>
    function DigestAsString(Format: TDECFormatClass = nil): string;
    /// <summary>
    ///   Returns the calculated hash value as formatted RawByteString
    /// </summary>
    /// <param name="Format">
    ///   Optional parameter. If a formatting class is being passed the formatting
    ///   will be applied to the returned string. Otherwise no formatting is
    ///   being used.
    /// </param>
    /// <returns>
    ///   Hash value of the last performed hash calculation
    /// </returns>
    /// <remarks>
    ///   We recommend to use a formatting which results in 7 bit ASCII chars
    ///   being returned, otherwise the conversion into the RawByteString might
    ///   result in strange characters in the returned result.
    /// </remarks>
    function DigestAsRawByteString(Format: TDECFormatClass = nil): RawByteString;

    /// <summary>
    ///   Calculates the hash value (digest) for a given buffer
    /// </summary>
    /// <param name="Buffer">
    ///   Untyped buffer the hash shall be calculated for
    /// </param>
    /// <param name="BufferSize">
    ///   Size of the buffer in byte
    /// </param>
    /// <returns>
    ///   Byte array with the calculated hash value
    /// </returns>
    function CalcBuffer(const Buffer; BufferSize: Integer): TBytes;
    /// <summary>
    ///   Calculates the hash value (digest) for a given buffer
    /// </summary>
    /// <param name="Data">
    ///   The TBytes array the hash shall be calculated on
    /// </param>
    /// <returns>
    ///   Byte array with the calculated hash value
    /// </returns>
    function CalcBytes(const Data: TBytes): TBytes;

    /// <summary>
    ///   Calculates the hash value (digest) for a given unicode string
    /// </summary>
    /// <param name="Value">
    ///   The string the hash shall be calculated on
    /// </param>
    /// <param name="Format">
    ///   Formatting class from DECFormat. The formatting will be applied to the
    ///   returned digest value. This parameter is optional.
    /// </param>
    /// <returns>
    ///   string with the calculated hash value
    /// </returns>
    function CalcString(const Value: string;
                        Format: TDECFormatClass = nil): string; overload;
    /// <summary>
    ///   Calculates the hash value (digest) for a given rawbytestring
    /// </summary>
    /// <param name="Value">
    ///   The string the hash shall be calculated on
    /// </param>
    /// <param name="Format">
    ///   Formatting class from DECFormat. The formatting will be applied to the
    ///   returned digest value. This parameter is optional.
    /// </param>
    /// <returns>
    ///   string with the calculated hash value
    /// </returns>
    function CalcString(const Value: RawByteString;
                        Format: TDECFormatClass): RawByteString; overload;

    /// <summary>
    ///   Returns the current value of the padding byte used to fill up data
    ///   if necessary
    /// </summary>
    function GetPaddingByte: Byte;
    /// <summary>
    ///   Changes the value of the padding byte used to fill up data
    ///   if necessary
    /// </summary>
    /// <param name="Value">
    ///   New value for the padding byte
    /// </param>
    procedure SetPaddingByte(Value: Byte);

    /// <summary>
    ///   Defines the byte used in the KDF methods to padd the end of the data
    ///   if the length of the data cannot be divided by required size for the
    ///   hash algorithm without reminder
    /// </summary>
    property PaddingByte: Byte read GetPaddingByte write SetPaddingByte;
  end;

  /// <summary>
  ///   Adds all methods which shall not be present in the specialized password
  ///   hash classes. Mostly the CalcStreamXX and CalcFileXXX ones.
  /// </summary>
  IDECHashExtended = Interface(IDECHash)
  ['{FCC6C79E-C32C-4520-967A-FD1E60572E0F}']
    /// <summary>
    ///   Calculates the hash value over a givens stream of bytes
    /// </summary>
    /// <param name="Stream">
    ///   Memory or file stream over which the hash value shall be calculated.
    ///   The stream must be assigned. The hash value will always be calculated
    ///   from the current position of the stream.
    /// </param>
    /// <param name="Size">
    ///   Number of bytes within the stream over which to calculate the hash value
    /// </param>
    /// <param name="HashResult">
    ///   In this byte array the calculated hash value will be returned
    /// </param>
    /// <param name="OnProgress">
    ///   Optional callback routine. It can be used to display the progress of
    ///   the operation.
    /// </param>
    procedure CalcStream(const Stream: TStream; Size: Int64; var HashResult: TBytes;
                         const OnProgress:TDECProgressEvent = nil); overload;
    /// <summary>
    ///   Calculates the hash value over a givens stream of bytes
    /// </summary>
    /// <param name="Stream">
    ///   Memory or file stream over which the hash value shall be calculated.
    ///   The stream must be assigned. The hash value will always be calculated
    ///   from the current position of the stream.
    /// </param>
    /// <param name="Size">
    ///   Number of bytes within the stream over which to calculate the hash value
    /// </param>
    /// <param name="Format">
    ///   Optional formatting class. The formatting of that will be applied to
    ///   the returned hash value.
    /// </param>
    /// <param name="OnProgress">
    ///   Optional callback routine. It can be used to display the progress of
    ///   the operation.
    /// </param>
    /// <returns>
    ///   Hash value over the bytes in the stream, formatted with the formatting
    ///   passed as format parameter, if used.
    /// </returns>
    function CalcStream(const Stream: TStream; Size: Int64; Format: TDECFormatClass = nil;
                        const OnProgress:TDECProgressEvent = nil): RawByteString; overload;

    /// <summary>
    ///   Calculates the hash value over a given stream of bytes. The calculated
    ///   hash value can be retrieved with one of the DigestAsXXX methods.
    /// </summary>
    /// <param name="Stream">
    ///   Memory or file stream over which the hash value shall be calculated.
    ///   The stream must be assigned. The hash value will always be calculated
    ///   from the current position of the stream.
    /// </param>
    /// <param name="Size">
    ///   Number of bytes within the stream over which to calculate the hash value
    /// </param>
    /// <param name="OnProgress">
    ///   Optional callback routine. It can be used to display the progress of
    ///   the operation.
    /// </param>
    /// <param name="DoFinalize">
    ///   Optinal parameter: if true this call is the last one and the
    ///   finalization of the hash calculation, including calling done, will be
    ///   carried out in this method call as well.
    /// </param>
    /// <remarks>
    ///   Before calling this method for the first time after creation of the
    ///   hash instance or after calling Done Init needs to be called.
    ///   After calling this method Done needs to be called and in case of
    ///   algorithms (like SHA3) with a message size in bits and not whole bytes
    ///   the contents of the last byte needs to be assigned to PaddingByte before
    ///   calling Done!
    /// </remarks>
    procedure CalcStream(const Stream: TStream; Size: Int64;
                         const OnProgress:TDECProgressEvent = nil;
                         DoFinalize: Boolean = false); overload;

    /// <summary>
    ///   Calculates the hash value over the contents of a given file
    /// </summary>
    /// <param name="FileName">
    ///   Path and name of the file to be processed
    /// </param>
    /// <param name="HashResult">
    ///   Here the resulting hash value is being returned as byte array
    /// </param>
    /// <param name="OnProgress">
    ///   Optional callback. If being used the hash calculation will call it from
    ///   time to time to return the current progress of the operation
    /// </param>
    procedure CalcFile(const FileName: string; var HashResult: TBytes;
                       const OnProgress:TDECProgressEvent = nil); overload;
    /// <summary>
    ///   Calculates the hash value over the contents of a given file
    /// </summary>
    /// <param name="FileName">
    ///   Path and name of the file to be processed
    /// </param>
    /// <param name="Format">
    ///   Optional parameter: Formatting class. If being used the formatting is
    ///   being applied to the returned string with the calculated hash value
    /// </param>
    /// <param name="OnProgress">
    ///   Optional callback. If being used the hash calculation will call it from
    ///   time to time to return the current progress of the operation
    /// </param>
    /// <returns>
    ///   Calculated hash value as RawByteString.
    /// </returns>
    /// <remarks>
    ///   We recommend to use a formatting which results in 7 bit ASCII chars
    ///   being returned, otherwise the conversion into the RawByteString might
    ///   result in strange characters in the returned result.
    /// </remarks>
    function CalcFile(const FileName: string; Format: TDECFormatClass = nil;
                      const OnProgress:TDECProgressEvent = nil): RawByteString; overload;
  end;

  /// <summary>
  ///   Interface for all hash classes which are able to operate on bit sized
  ///   message lengths instead of byte sized ones only.
  /// </summary>
  IDECHashBitsized = Interface(IDECHashExtended)
  ['{7F2232CB-C3A7-4A14-858B-D98AB61E04E4}']
    /// <summary>
    ///   Returns the number of bits the final byte of the message consists of
    /// </summary>
    function GetFinalByteLength: UInt8;
    /// <summary>
    ///   Sets the number of bits the final byte of the message consists of
    /// </summary>
    procedure SetFinalByteLength(const Value: UInt8);

    /// <summary>
    ///   Setting this to a number of bits allows to process messages which have
    ///   a length which is not a exact multiple of bytes.
    /// </summary>
    property FinalBitLength : UInt8
      read   GetFinalByteLength
      write  SetFinalByteLength;
  end;

  /// <summary>
  ///   Interface for all hash classes which provide a variable output length for
  ///   the calculated hash value
  /// </summary>
  IDECHashExtensibleOutput = Interface(IDECHash)
  ['{C832E9AB-961C-4888-A607-9EC0780B3F8C}']
    /// <summary>
    ///   Returns the length of the calculated hash value in byte
    /// </summary>
    function  GetHashSize: UInt16;
    /// <summary>
    ///   Defines the length of the calculated hash value
    /// </summary>
    /// <param name="Value">
    ///   Length of the hash value to be returned in byte
    /// </param>
    procedure SetHashSize(const Value: UInt16);
    /// <summary>
    ///   Define the lenght of the resulting hash value in byte as these functions
    ///   are extendable output functions
    /// </summary>
    property HashSize : UInt16
      read   GetHashSize
      write  SetHashSize;
  end;

  /// <summary>
  ///   Interface for all hash classes which have a rounds property.
  /// </summary>
  IDECHashRounds = Interface(IDECHash)
  ['{22864693-0DC6-41AF-8188-192B770B4717}']
    /// <summary>
    ///   Returns the minimum possible number for the rounds parameter.
    ///   Value depends on Digest size which depends on concrete implementation
    /// </summary>
    function GetMinRounds: UInt32;
    /// <summary>
    ///   Returns the maximum possible number for the rounds parameter.
    ///   Value depends on Digest size which depends on concrete implementation
    /// </summary>
    function GetMaxRounds: UInt32;

     /// <summary>
    ///   Sets the number of rounds for the looping over the data
    /// </summary>
    procedure SetRounds(Value: UInt32);
    /// <summary>
    ///   Returns the number of rounds the calculation will perform
    /// </summary>
    function  GetRounds: UInt32;

    /// <summary>
    ///   Define the number of rounds for the calculation.
    /// </summary>
    property Rounds: UInt32
      read   GetRounds
      write  SetRounds;
  end;

  /// <summary>
  ///   Interface for passwordn hash algorithms
  /// </summary>
  IDECHashPassword = Interface(IDECHash)
  ['{B4D8A80C-1F42-46F8-9288-D71ECCFE6F02}']
      /// <summary>
    ///   Calculates a passwort hash for the given password and returns it in
    ///   a BSDCrypt compatible format. This method only works for those hash
    ///   algorithms implementing the necessary GetBSDCryptID method.
    /// </summary>
    /// <param name="Password">
    ///   Entered password for which to calculate the hash. The caller is
    ///   responsible to ensure the maximum password length is adhered to.
    ///   Any exceptions raised due to too long passwords are not caught here!
    /// </param>
    /// <param name="Params">
    ///   Algorithm specific parameters used for initialization. For details see
    ///   documentation of the concrete implementation in the algorithm.
    /// </param>
    /// <param name="Salt">
    ///   Salt value used by the password hash calculation. Depending on the
    ///   value of SaltIsRaw, the salt needs to specified in raw encoding or
    ///   in the encoding used in the Crypt/BSD password storage string.
    /// </param>
    /// <param name="SaltIsRaw">
    ///   If true the passed salt value is a raw value. If false it is encoded
    ///   like in the Crypt/BSD password storage string.
    /// </param>
    /// <param name="Format">
    ///   Formatting class used to format the calculated password. Different
    ///   algorithms in BSDCrypt use different algorithms so one needs to know
    ///   which one to pass. See description of the hash class used.
    /// </param>
    /// <returns>
    ///   Calculated hash value in BSD crypt style format. Returns an empty
    ///   string if the algorithm is not a Crypt/BSD style password hash algorithm.
    /// </returns>
    /// <exception cref="EDECHashException">
    ///   Exception raised if length of <c>Password</c> is higher than
    ///   <c>MaxPasswordLength</c> or if a salt with a different length than
    ///   128 bit has been specified.
    /// </exception>
    function GetDigestInCryptFormat(const Password : string;
                                    const Params   : string;
                                    const Salt     : string;
                                    SaltIsRaw      : Boolean;
                                    Format         : TDECFormatClass):string;

    /// <summary>
    ///   Checks whether a given password is the correct one for a password
    ///   storage "record"/entry in Crypt/BSD format.
    /// </summary>
    /// <param name="Password">
    ///   Password to check for validity
    /// </param>
    /// <param name="CryptData">
    ///   The data needed to "compare" the password against in Crypt/BSD like
    ///   format: $<id>[$<param>=<value>(,<param>=<value>)*][$<salt>[$<hash>]].
    ///   The exact format depends on the algorithm used.
    /// </param>
    /// <param name="Format">
    ///   Must be the right type for the Crypt/BSD encoding used by the
    ///   algorithm used. This was implemented this way to avoid making the
    ///   DECHashAuthentication unit dependant on the DECFormat unit not needed
    ///   otherwise.
    /// </param>
    /// <returns>
    ///    True if the password given is correct.
    /// </returns>
    function IsValidPassword(const Password  : string;
                             const CryptData : string;
                             Format          : TDECFormatClass): Boolean;
    /// <summary>
    ///   Sets the salt value given. Throws an EDECHashException if a salt is
    ///   passed which is longer than MaxSaltLength.
    /// </summary>
    /// <exception cref="EDECHashException">
    ///   Exception raised if length of  <c>Value</c> is not in the range of
    ///   <c>MinSaltLength</c> and <c>MaxSaltLength</c>
    /// </exception>
    procedure SetSalt(const Value: TBytes);
    /// <summary>
    ///   Returns the defined salt value
    /// </summary>
    function  GetSalt: TBytes;
    /// <summary>
    ///   Defines the salt value used. Throws an EDECHashException if a salt is
    ///   passed which is longer than MaxSaltLength. The salt has to be passed
    ///   in binary form. Any Base64 encoded salt needs to be decoded before
    ///   passing.
    /// </summary>
    /// <exception cref="EDECHashException">
    ///   Exception raised if the length of the value assigned is not in the
    ///   range of <c>MinSaltLength</c> and <c>MaxSaltLength</c>
    /// </exception>
    property Salt: TBytes
      read   GetSalt
      write  SetSalt;
  end;

implementation

end.

