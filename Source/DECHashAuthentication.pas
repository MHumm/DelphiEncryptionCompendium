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

/// <summary>
///   Unit containing all the KDF, MGF, HMAC and PBKDF2 algorithms
/// </summary>
unit DECHashAuthentication;
{$INCLUDE DECOptions.inc}

interface

uses
  {$IFDEF FPC}
  SysUtils, Classes,
  {$ELSE}
  System.SysUtils, System.Classes, Generics.Collections,
  {$ENDIF}
  DECBaseClass, DECHashBase, DECHashInterface, DECTypes , DECFormatBase;


type
  /// <summary>
  ///   Type of the KDF variant
  /// </summary>
  TKDFType = (ktKDF1, ktKDF2, ktKDF3);

  /// <summary>
  ///   Meta class for the class containing the password hash specific properties
  /// </summary>
  TDECPasswordHashClass = class of TDECPasswordHash;

  /// <summary>
  ///   Class containing all the KDF, MGF, HMAC and PBKDF2 algorithms
  /// </summary>
  TDECHashAuthentication = class(TDECHash)
  strict private
    /// <summary>
    ///   Key deviation algorithm to derrive keys from other keys.
    ///   IEEE P1363 Working Group, ISO 18033-2:2004
    ///   This is either KDF1 or KDF2 depending on KDFType
    /// </summary>
    /// <param name="Data">
    ///   Source data from which the new key shall be derrived.
    /// </param>
    /// <param name="DataSize">
    ///   Size in bytes of the source data passed.
    /// </param>
    /// <param name="Seed">
    ///   Start value for pseudo random number generator
    /// </param>
    /// <param name="SeedSize">
    ///   Size of the seed in byte.
    /// </param>
    /// <param name="MaskSize">
    ///   Size of the generated output in byte
    /// </param>
    /// <param name="KDFType">
    ///   Type of the algorithm: 1 = KDF1, 2 = KDF2 and 3 = KDF 3
    /// </param>
    /// <returns>
    ///   Returns the new derrived key.
    /// </returns>
    class function KDFInternal(const Data; DataSize: Integer; const Seed;
                               SeedSize, MaskSize: Integer;
                               KDFType: TKDFType): TBytes; inline;
  public
    /// <summary>
    ///   Detects whether the given hash class is one particularily suited
    ///   for storing hashes of passwords
    /// </summary>
    /// <returns>
    ///   true if it's a hash class specifically designed to store password
    ///   hashes, false for ordinary hash algorithms.
    /// </returns>
    class function IsPasswordHash: Boolean; override;

    // mask generation

    /// <summary>
    ///   Mask generation: generates an output based on the data given which is
    ///   similar to a hash function but in contrast does not have a fixed output
    ///   length. Use of a MGF is desirable in cases where a fixed-size hash
    ///   would be inadequate. Examples include generating padding, producing
    ///   one time pads or keystreams in symmetric key encryption, and yielding
    ///   outputs for pseudorandom number generators.
    ///   Indexed Mask generation function, IEEE P1363 working group
    ///   equal to KDF1 except without seed. RFC 2437 PKCS #1
    /// </summary>
    /// <param name="Data">
    ///   Data from which to generate a mask from
    /// </param>
    /// <param name="DataSize">
    ///   Size of the input data in bytes
    /// </param>
    /// <param name="MaskSize">
    ///   Size of the returned mask in bytes
    /// </param>
    /// <returns>
    ///   Mask such that one cannot determine the data which had been given to
    ///   generate this mask from.
    /// </returns>
    class function MGF1(const Data; DataSize, MaskSize: Integer): TBytes; overload;
    /// <summary>
    ///   Mask generation: generates an output based on the data given which is
    ///   similar to a hash function but in contrast does not have a fixed output
    ///   length. Use of a MGF is desirable in cases where a fixed-size hash
    ///   would be inadequate. Examples include generating padding, producing
    ///   one time pads or keystreams in symmetric key encryption, and yielding
    ///   outputs for pseudorandom number generators
    /// </summary>
    /// <param name="Data">
    ///   Data from which to generate a mask from
    /// </param>
    /// <param name="MaskSize">
    ///   Size of the returned mask in bytes
    /// </param>
    /// <returns>
    ///   Mask such that one cannot determine the data which had been given to
    ///   generate this mask from.
    /// </returns>
    class function MGF1(const Data: TBytes; MaskSize: Integer): TBytes; overload;

    /// <summary>
    ///   Key deviation algorithm to derrive keys from other keys.
    ///   IEEE P1363 Working Group, ISO 18033-2:2004
    /// </summary>
    /// <param name="Data">
    ///   Source data from which the new key shall be derrived.
    /// </param>
    /// <param name="DataSize">
    ///   Size in bytes of the source data passed.
    /// </param>
    /// <param name="Seed">
    ///   Salt value
    /// </param>
    /// <param name="SeedSize">
    ///   Size of the seed/salt in byte.
    /// </param>
    /// <param name="MaskSize">
    ///   Size of the generated output in byte
    /// </param>
    /// <returns>
    ///   Returns the new derrived key with the length specified in MaskSize.
    /// </returns>
    /// <remarks>
    ///   In earlier versions there was an optional format parameter. This has
    ///   been removed as this is a base class. The method might not have
    ///   returned a result with the MaskSize specified, as the formatting might
    ///   have had to alter this. This would have been illogical.
    /// </remarks>
    class function KDF1(const Data; DataSize: Integer; const Seed;
                        SeedSize, MaskSize: Integer): TBytes; overload;

    /// <summary>
    ///   Key deviation algorithm to derrive keys from other keys.
    ///   IEEE P1363 Working Group, ISO 18033-2:2004
    /// </summary>
    /// <param name="Data">
    ///   Source data from which the new key shall be derrived.
    /// </param>
    /// <param name="Seed">
    ///   Salt value
    /// </param>
    /// <param name="MaskSize">
    ///   Size of the generated output in byte
    /// </param>
    /// <returns>
    ///   Returns the new derrived key with the length specified in MaskSize.
    /// </returns>
    class function KDF1(const Data, Seed: TBytes;
                        MaskSize: Integer): TBytes; overload;

    /// <summary>
    ///   Key deviation algorithm to derrive keys from other keys.
    ///   IEEE P1363 Working Group, ISO 18033-2:2004
    /// </summary>
    /// <param name="Data">
    ///   Source data from which the new key shall be derrived.
    /// </param>
    /// <param name="DataSize">
    ///   Size in bytes of the source data passed.
    /// </param>
    /// <param name="Seed">
    ///   Salt value
    /// </param>
    /// <param name="SeedSize">
    ///   Size of the seed/salt in byte.
    /// </param>
    /// <param name="MaskSize">
    ///   Size of the generated output in byte
    /// </param>
    /// <returns>
    ///   Returns the new derrived key with the length specified in MaskSize.
    /// </returns>
    /// <remarks>
    ///   In earlier versions there was an optional format parameter. This has
    ///   been removed as this is a base class. The method might not have
    ///   returned a result with the MaskSize specified, as the formatting might
    ///   have had to alter this. This would have been illogical.
    /// </remarks>
    class function KDF2(const Data; DataSize: Integer; const Seed;
                        SeedSize, MaskSize: Integer): TBytes; overload;

    /// <summary>
    ///   Key deviation algorithm to derrive keys from other keys.
    ///   IEEE P1363 Working Group, ISO 18033-2:2004
    /// </summary>
    /// <param name="Data">
    ///   Source data from which the new key shall be derrived.
    /// </param>
    /// <param name="Seed">
    ///   Start value for pseudo random number generator
    /// </param>
    /// <param name="MaskSize">
    ///   Size of the generated output in byte
    /// </param>
    /// <returns>
    ///   Returns the new derrived key with the length specified in MaskSize.
    /// </returns>
    class function KDF2(const Data, Seed: TBytes;
                        MaskSize: Integer): TBytes; overload;

    /// <summary>
    ///   Key deviation algorithm to derrive keys from other keys.
    /// </summary>
    /// <param name="Data">
    ///   Source data from which the new key shall be derrived.
    /// </param>
    /// <param name="DataSize">
    ///   Size in bytes of the source data passed.
    /// </param>
    /// <param name="Seed">
    ///   Salt value
    /// </param>
    /// <param name="SeedSize">
    ///   Size of the seed/salt in byte.
    /// </param>
    /// <param name="MaskSize">
    ///   Size of the generated output in byte
    /// </param>
    /// <returns>
    ///   Returns the new derrived key with the length specified in MaskSize.
    /// </returns>
    /// <remarks>
    ///   In earlier versions there was an optional format parameter. This has
    ///   been removed as this is a base class. The method might not have
    ///   returned a result with the MaskSize specified, as the formatting might
    ///   have had to alter this. This would have been illogical.
    /// </remarks>
    class function KDF3(const Data; DataSize: Integer; const Seed;
                        SeedSize, MaskSize: Integer): TBytes; overload;

    /// <summary>
    ///   Key deviation algorithm to derrive keys from other keys.
    /// </summary>
    /// <param name="Data">
    ///   Source data from which the new key shall be derrived.
    /// </param>
    /// <param name="Seed">
    ///   Salt value
    /// </param>
    /// <param name="MaskSize">
    ///   Size of the generated output in byte
    /// </param>
    /// <returns>
    ///   Returns the new derrived key with the length specified in MaskSize.
    /// </returns>
    class function KDF3(const Data, Seed: TBytes;
                        MaskSize: Integer): TBytes; overload;

    // DEC's own KDF + MGF

    /// <summary>
    ///   Key deviation algorithm to derrive keys from other keys. The alrorithm
    ///   implemented by this method does not follow any official standard.
    /// </summary>
    /// <param name="Data">
    ///   Source data from which the new key shall be derrived.
    /// </param>
    /// <param name="DataSize">
    ///   Size in bytes of the source data passed.
    /// </param>
    /// <param name="Seed">
    ///   Salt value
    /// </param>
    /// <param name="SeedSize">
    ///   Size of the seed/salt in byte.
    /// </param>
    /// <param name="MaskSize">
    ///   Size of the generated output in byte
    /// </param>
    /// <param name="Index">
    ///   Optional parameter: can be used to specify a different default value
    ///   for the index variable used in the algorithm.
    /// </param>
    /// <returns>
    ///   Returns the new derrived key with the length specified in MaskSize.
    /// </returns>
    class function KDFx(const Data; DataSize: Integer; const Seed;
                        SeedSize, MaskSize: Integer;
                        Index: UInt32 = 1): TBytes; overload;
    /// <summary>
    ///   Key deviation algorithm to derrive keys from other keys.
    /// </summary>
    /// <remarks>
    ///   This variant of the algorithm does not follow an official standard.
    ///   It has been created by the original author of DEC.
    /// </remarks>
    /// <param name="Data">
    ///   Source data from which the new key shall be derrived.
    /// </param>
    /// <param name="Seed">
    ///   Salt value
    /// </param>
    /// <param name="MaskSize">
    ///   Size of the generated output in byte
    /// </param>
    /// <param name="Index">
    ///   Optional parameter: can be used to specify a different default value
    ///   for the index variable used in the algorithm.
    /// </param>
    /// <returns>
    ///   Returns the new derrived key with the length specified in MaskSize.
    /// </returns>
    class function KDFx(const Data, Seed: TBytes; MaskSize: Integer;
                        Index: UInt32 = 1): TBytes; overload;

    /// <summary>
    ///   Mask generation: generates an output based on the data given which is
    ///   similar to a hash function but in contrast does not have a fixed output
    ///   length. Use of a MGF is desirable in cases where a fixed-size hash
    ///   would be inadequate. Examples include generating padding, producing
    ///   one time pads or keystreams in symmetric key encryption, and yielding
    ///   outputs for pseudorandom number generators.
    /// </summary>
    /// <remarks>
    ///   This variant of the algorithm does not follow an official standard.
    ///   It has been created by the original author of DEC.
    /// </remarks>
    /// <param name="Data">
    ///   Data from which to generate a mask from
    /// </param>
    /// <param name="DataSize">
    ///   Size of the passed data in bytes
    /// </param>
    /// <param name="MaskSize">
    ///   Size of the returned mask in bytes
    /// </param>
    /// <param name="Index">
    ///   Looks like this is a salt applied to each byte of output data?
{ TODO : Clarify this parameter }
    /// </param>
    /// <returns>
    ///   Mask such that one cannot determine the data which had been given to
    ///   generate this mask from.
    /// </returns>
    class function MGFx(const Data; DataSize, MaskSize: Integer;
                        Index: UInt32 = 1): TBytes; overload;
    /// <summary>
    ///   Mask generation: generates an output based on the data given which is
    ///   similar to a hash function but in contrast does not have a fixed output
    ///   length. Use of a MGF is desirable in cases where a fixed-size hash
    ///   would be inadequate. Examples include generating padding, producing
    ///   one time pads or keystreams in symmetric key encryption, and yielding
    ///   outputs for pseudorandom number generators.
    /// </summary>
    /// <remarks>
    ///   This variant of the algorithm does not follow an official standard.
    ///   It has been created by the original author of DEC.
    /// </remarks>
    /// <param name="Data">
    ///   Data from which to generate a mask from
    /// </param>
    /// <param name="MaskSize">
    ///   Size of the returned mask in bytes
    /// </param>
    /// <param name="Index">
    ///   Looks like this is a salt applied to each byte of output data?
{ TODO : Clarify this parameter }
    /// </param>
    /// <returns>
    ///   Mask such that one cannot determine the data which had been given to
    ///   generate this mask from.
    /// </returns>
    class function MGFx(const Data: TBytes; MaskSize: Integer;
                        Index: UInt32 = 1): TBytes; overload;

    /// <summary>
    ///   HMAC according to rfc2202: hash message authentication code allow to
    ///   verify both the data integrity and the authenticity of a message.
    /// </summary>
    /// <param name="Key">
    ///   This is the secret key which shall not be transmitted over the line.
    ///   The sender uses this key to create the resulting HMAC, transmits the
    ///   text and the HMAC over the line and the receiver recalculates the HMAC
    ///   based on his copy of the secret key. If his calculated HMAC equals the
    ///   transfered HMAC value the message has not been tampered.
    /// </param>
    /// <param name="Text">
    ///   Text over which to calculate the HMAC
    /// </param>
    /// <returns>
    ///   Calculated HMAC
    /// </returns>
    class function HMAC(const Key, Text: TBytes): TBytes; overload;

    /// <summary>
    ///   HMAC according to rfc2202: hash message authentication code allow to
    ///   verify both the data integrity and the authenticity of a message.
    /// </summary>
    /// <param name="Key">
    ///   This is the secret key which shall not be transmitted over the line.
    ///   The sender uses this key to create the resulting HMAC, transmits the
    ///   text and the HMAC over the line and the receiver recalculates the HMAC
    ///   based on his copy of the secret key. If his calculated HMAC equals the
    ///   transfered HMAC value the message has not been tampered.
    /// </param>
    /// <param name="Text">
    ///   Text over which to calculate the HMAC
    /// </param>
    /// <returns>
    ///   Calculated HMAC
    /// </returns>
    class function HMAC(const Key, Text: RawByteString): TBytes; overload;

    /// <summary>
    ///   Password based key deviation function 2
    ///   RFC 2898, PKCS #5.
    ///   This can be used to create a login sheme by storing the output,
    ///   number of iterations and the salt. When the user enters a password
    ///   this calculation is done using the same parameters as stored for his
    ///   user account and comparing the output.
    /// </summary>
    /// <param name="Password">
    ///   Password to create the deviation from
    /// </param>
    /// <param name="Salt">
    ///   Salt used to modify the password
    /// </param>
    /// <param name="Iterations">
    ///   Number of iterations to perform
    /// </param>
    /// <param name="KeyLength">
    ///   Length of the resulting key in byte
    /// </param>
    /// <returns>
    ///   The calculated PBKDF2 value
    /// </returns>
    class function PBKDF2(const Password, Salt: TBytes; Iterations: Integer;
                          KeyLength: Integer): TBytes; overload;

    /// <summary>
    ///   Password based key deviation function 2
    ///   RFC 2898, PKCS #5.
    ///   This can be used to create a login sheme by storing the output,
    ///   number of iterations and the salt. When the user enters a password
    ///   this calculation is done using the same parameters as stored for his
    ///   user account and comparing the output.
    /// </summary>
    /// <param name="Password">
    ///   Password to create the deviation from
    /// </param>
    /// <param name="Salt">
    ///   Salt used to modify the password
    /// </param>
    /// <param name="Iterations">
    ///   Number of iterations to perform
    /// </param>
    /// <param name="KeyLength">
    ///   Length of the resulting key in byte
    /// </param>
    /// <returns>
    ///   The calculated PBKDF2 value
    /// </returns>
    class function PBKDF2(const Password, Salt: RawByteString;
                          Iterations: Integer;
                          KeyLength: Integer): TBytes; overload;
  end;

  /// <summary>
  ///   Adds methods which shall not be found in the specialized password hash
  ///   classes. Mainly the CalcStreamXXX and CalcFileXXX ones. They shall not
  ///   be contained there as those password hashes usually restrict the maximum
  ///   length of the data which can be hashed.
  /// </summary>
  TDECHashExtended = class(TDECHashAuthentication, IDECHashExtended)
    /// <summary>
    ///   Calculates the hash value over a given stream of bytes
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
    ///   In this byte array the calculated hash value will be returned. The
    ///   array will be automatically sized suitably.
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
  ///   All hash classes with hash algorithms specially developed for password
  ///   hashing should inherit from this class in order to be able to distinguish
  ///   those from normal hash algorithms not really meant to be used for password
  ///   hashing.
  /// </summary>
  TDECPasswordHash = class(TDECHashAuthentication, IDECHashPassword)
  strict private
    /// <summary>
    ///   Sets the salt value given. Throws an EDECHashException if a salt is
    ///   passed which is longer than MaxSaltLength.
    /// </summary>
    /// <exception cref="EDECHashException">
    ///   Exception raised if length of <c>Value</c> is not in the range of
    ///   <c>MinSaltLength</c> and <c>MaxSaltLength</c>
    /// </exception>
    procedure SetSalt(const Value: TBytes);
    /// <summary>
    ///   Returns the defined salt value
    /// </summary>
    function  GetSalt: TBytes;
  strict protected
    /// <summary>
    ///   Most, if not all password hashing algorithms (like bcrypt) have a salt
    ///   parameter to modify the entered password value.
    /// </summary>
    FSalt : TBytes;

    /// <summary>
    ///   Overwrite the salt value
    /// </summary>
    procedure DoDone; override;

    {$Region CryptFormatHandling}
    /// <summary>
    ///   Returns the ID code for Crypt/BSD like storing of passwords. The ID
    ///   has to start with the $ at the beginning and does not contain a
    ///   trailing $.
    /// </summary>
    /// <returns>
    ///   If the algorithm on which this is being used is a Crypt/BSD compatible
    ///   password hash algorithm the ID is returned otherwise an empty string.
    /// </returns>
    class function GetCryptID:string; virtual;

    /// <summary>
    ///   Returns the parameters required for the crypt-like password storing
    ///   in that format.
    /// </summary>
    /// <param name="Params">
    ///   Algorithm specific parameters used for initialization. For details see
    ///   documentation of the concrete implementation in the algorithm.
    /// </param>
    /// <param name="Format">
    ///   Format class for formatting the output
    /// </param>
    /// <returns>
    ///   Returns an empty string if the the algorithm on which this is being
    ///   used is not a Crypt/BSD compatible password hash algorithm
    /// </returns>
    function GetCryptParams(const Params : string;
                            Format       : TDECFormatClass):string; virtual;
    /// <summary>
    ///   Returns the salt required for the crypt-like password storing
    ///   in that format.
    /// </summary>
    /// <param name="Salt">
    ///   The raw salt value
    /// </param>
    /// <param name="Format">
    ///   Format class for formatting the output
    /// </param>
    function GetCryptSalt(const Salt : TBytes;
                          Format     : TDECFormatClass):string; virtual;
    /// <summary>
    ///   Returns the hash required for the crypt-like password storing
    ///   in that format. If a salt etc. is needed that needs to be scepcified
    ///   before calling this method.
    /// </summary>
    /// <param name="Password">
    ///   Password entered which shall be hashed.
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
    /// <param name="Salt">
    ///   Salt value used by the password hash calculation in binary raw format,
    ///   means not Radix64 encoded or so.
    /// </param>
    /// <param name="Format">
    ///   Format class for formatting the output
    /// </param>
    /// <returns>
    ///   Returns an empty string if the the algorithm on which this is being
    ///   used is not a Crypt/BSD compatible password hash algorithm.
    /// </returns>
    function GetCryptHash(Password     : TBytes;
                          const Params : string;
                          const Salt   : TBytes;
                          Format       : TDECFormatClass):string; virtual;
    {$EndRegion}
  public
    /// <summary>
    ///   Returns the maximum length of a salt value given for the algorithm
    ///   in byte
    /// </summary>
    function MaxSaltLength:UInt8; virtual; abstract;
    /// <summary>
    ///   Returns the minimum length of a salt value given for the algorithm
    ///   in byte
    /// </summary>
    function MinSaltLength:UInt8; virtual; abstract;
    /// <summary>
    ///   Returns the maximum length of a user supplied password given for the
    ///   algorithm in byte
    /// </summary>
    class function MaxPasswordLength:UInt8; virtual; abstract;

    {$Region CryptBSDFormatHandlingPublic}
    /// <summary>
    ///   Tries to find a class type by its Crypt identification
    ///   (e.g. 2a is Bcrypt).
    /// </summary>
    /// <param name="Identity">
    ///   Identity to look for, with or without the starting $ delimiter sign.
    /// </param>
    /// <returns>
    ///   Returns the class type of the class with the specified identity value
    ///   or throws an EDECClassNotRegisteredException exception if no class
    ///   with the given Crypt identity has been found
    /// </returns>
    /// <exception cref="EDECClassNotRegisteredException">
    ///   Exception raised if the class specified by <c>Identity</c> is not found
    /// </exception>
    class function ClassByCryptIdentity(Identity: string): TDECPasswordHashClass;

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
                                    Format         : TDECFormatClass):string; overload;

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
    function GetDigestInCryptFormat(Password     : TBytes;
                                    const Params : string;
                                    const Salt   : string;
                                    SaltIsRaw    : Boolean;
                                    Format       : TDECFormatClass):string; overload; virtual;

    /// <summary>
    ///   Checks whether a given password is the correct one for a password
    ///   storage "record"/entry in Crypt/BSD format.
    /// </summary>
    /// <param name="Password">
    ///   Password to check for validity
    /// </param>
    /// <param name="CryptData">
    ///   The data needed to "compare" the password against in Crypt/BSD like
    ///   format: $<id>[$<param>=<value>(,<param>=<value>)*][$<salt>[$<hash>]]
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
                             Format          : TDECFormatClass): Boolean; overload;

    /// <summary>
    ///   Checks whether a given password is the correct one for a password
    ///   storage "record"/entry in Crypt/BSD format.
    /// </summary>
    /// <param name="Password">
    ///   Password to check for validity
    /// </param>
    /// <param name="CryptData">
    ///   The data needed to "compare" the password against in Crypt/BSD like
    ///   format: $<id>[$<param>=<value>(,<param>=<value>)*][$<salt>[$<hash>]]
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
    function IsValidPassword(Password        : TBytes;
                             const CryptData : string;
                             Format          : TDECFormatClass): Boolean; overload; virtual;
    {$EndRegion}

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

  {$IFNDEF HAVE_ASSIGN_ARRAY}
  /// <summary>
  ///   Class helper for implementing array concatenation which is not available
  ///   in Delphi XE6 or lower.
  /// </summary>
  /// <remarks>
  ///   Shall be removed as soon as the minimum supported version is XE7 or higher.
  /// </remarks>
  TArrHelper = class
    class procedure AppendArrays<T>(var A: TArray<T>; const B: TArray<T>);
  end;
  {$ENDIF}

  /// <summary>
  ///   Meta class for the class containing the authentication methods
  /// </summary>
  TDECHashAuthenticationClass = class of TDECHashAuthentication;
  /// <summary>
  ///   Meta class for the class containing the additional calculation methods
  /// </summary>
  TDECHashExtendedClass = class of TDECHashExtended;

  /// <summary>
  /// Returns the passed class type if it is not nil. Otherwise the class type
  /// of the TFormat_Copy class is being returned.
  /// </summary>
  /// <param name="HashClass">
  ///   Class type of a Hash class to return by ValidAuthenticationHash if
  ///   passing nil to that one. This parameter should not be nil!
  /// </param>
  /// <returns>
  /// Passed class type or TFormat_Copy class type, depending on FormatClass
  /// parameter value.
  /// </returns>
  function ValidAuthenticationHash(HashClass: TDECHashClass): TDECHashAuthenticationClass;
  /// <summary>
  ///   Defines which hash class to return by ValidAuthenticationHash if passing
  ///   nil to that
  /// </summary>
  /// <param name="HashClass">
  ///   Class type of a Hash class to return by ValidAuthenticationHash if
  ///   passing nil to that one. This parameter should not be nil!
  /// </param>
  procedure SetDefaultAuthenticationHashClass(HashClass: TDECHashClass);

implementation

uses
  DECUtil;

resourcestring
  /// <summary>
  ///   Exception message when specifying a salt value longer than allowed
  /// </summary>
  sSaltValueTooLong     = 'Maximum allowed salt length (%0:d byte) exceeded';
  /// <summary>
  ///   Exception message when specifying a salt value shorter than allowed
  /// </summary>
  sSaltValueTooShort    = 'Minumum allowed salt length (%0:d byte) exceeded';
  /// <summary>
  ///   No class for the given crypt ID has been registered, so that ID is
  ///   not supported.
  /// </summary>
  sCryptIDNotRegistered = 'No class for crypt ID %s registered';
  /// <summary>
  ///   Exception message used when no default class has been defined
  /// </summary>
  sAuthHashNoDefault    = 'No default authentication hash class has been registered';

var
  /// <summary>
  ///   Hash class returned by ValidAuthenticationHash if nil is passed as
  ///   parameter to it
  /// </summary>
  FDefaultAutheticationHashClass: TDECHashAuthenticationClass = nil;

class function TDECHashAuthentication.IsPasswordHash: Boolean;
begin
  Result := self.InheritsFrom(TDECPasswordHash);
end;

class function TDECHashAuthentication.KDFInternal(const Data; DataSize: Integer; const Seed;
                             SeedSize, MaskSize: Integer; KDFType: TKDFType): TBytes;
var
  I, n,
  Rounds, DigestBytes : Integer;
  Count               : UInt32;
  HashInstance        : TDECHashAuthentication;
begin
  SetLength(Result, 0);
  DigestBytes := DigestSize;
  Assert(MaskSize >= 0);
  Assert(DataSize >= 0);
  Assert(SeedSize >= 0);
  Assert(DigestBytes >= 0);

  HashInstance := TDECHashAuthenticationClass(self).Create;
  try
    Rounds := (MaskSize + DigestBytes - 1) div DigestBytes;
    SetLength(Result, Rounds * DigestBytes);

    if (KDFType = ktKDF2) then
      n := 1
    else
      n := 0;

    for I := 0 to Rounds-1 do
    begin
      Count := SwapUInt32(n);
      HashInstance.Init;

      if (KDFType = ktKDF3) then
      begin
        HashInstance.Calc(Count, SizeOf(Count));
        HashInstance.Calc(Data, DataSize);
      end
      else
      begin
        HashInstance.Calc(Data, DataSize);
        HashInstance.Calc(Count, SizeOf(Count));
      end;

      HashInstance.Calc(Seed, SeedSize);
      HashInstance.Done;
      Move(HashInstance.Digest[0], Result[(I) * DigestBytes], DigestBytes);

      inc(n);
    end;

    SetLength(Result, MaskSize);
  finally
    HashInstance.Free;
  end;
end;

class function TDECHashAuthentication.MGF1(const Data; DataSize, MaskSize: Integer): TBytes;
begin
  Result := KDF1(Data, DataSize, NullStr, 0, MaskSize);
end;

class function TDECHashAuthentication.MGF1(const Data: TBytes; MaskSize: Integer): TBytes;
begin
  Result := KDFInternal(Data[0], Length(Data), NullStr, 0, MaskSize, ktKDF1);
end;

class function TDECHashAuthentication.KDF1(const Data; DataSize: Integer; const Seed;
  SeedSize, MaskSize: Integer): TBytes;
begin
  Result := KDFInternal(Data, DataSize, Seed, SeedSize, MaskSize, ktKDF1);
end;

class function TDECHashAuthentication.KDF1(const Data, Seed: TBytes;
  MaskSize: Integer): TBytes;
begin
  if (length(Seed) > 0) then
    Result := KDFInternal(Data[0], length(Data), Seed[0], length(Seed), MaskSize, ktKDF1)
  else
    Result := KDFInternal(Data[0], length(Data), NullStr, 0, MaskSize, ktKDF1);
end;

class function TDECHashAuthentication.KDF2(const Data; DataSize: Integer; const Seed;
                             SeedSize, MaskSize: Integer): TBytes;
begin
  Result := KDFInternal(Data, DataSize, Seed, SeedSize, MaskSize, ktKDF2);
end;

class function TDECHashAuthentication.KDF2(const Data, Seed: TBytes;
                                           MaskSize: Integer): TBytes;
begin
  if (length(Seed) > 0) then
    Result := KDFInternal(Data[0], Length(Data), Seed[0], Length(Seed), MaskSize, ktKDF2)
  else
    Result := KDFInternal(Data[0], Length(Data), NullStr, 0, MaskSize, ktKDF2);
end;

class function TDECHashAuthentication.KDF3(const Data; DataSize: Integer;
                                           const Seed; SeedSize, MaskSize: Integer): TBytes;
begin
  Result := KDFInternal(Data, DataSize, Seed, SeedSize, MaskSize, ktKDF3);
end;

class function TDECHashAuthentication.KDF3(const Data, Seed: TBytes;
                                           MaskSize: Integer): TBytes;
begin
  if (length(Seed) > 0) then
    Result := KDFInternal(Data[0], Length(Data), Seed[0], Length(Seed), MaskSize, ktKDF3)
  else
    Result := KDFInternal(Data[0], Length(Data), NullStr, 0, MaskSize, ktKDF3);
end;

class function TDECHashAuthentication.KDFx(const Data; DataSize: Integer;
                                           const Seed; SeedSize, MaskSize: Integer;
                                           Index: UInt32 = 1): TBytes;
// DEC's own KDF, even stronger
var
  I, J         : Integer;
  Count        : UInt32;
  R            : Byte;
  HashInstance : TDECHashAuthentication;
begin
  Assert(MaskSize >= 0);
  Assert(DataSize >= 0);
  Assert(SeedSize >= 0);
  Assert(DigestSize > 0);

  SetLength(Result, MaskSize);
  Index := SwapUInt32(Index);

  HashInstance := TDECHashAuthenticationClass(self).Create;
  try
    for I := 0 to MaskSize - 1 do
    begin
      HashInstance.Init;

      Count := SwapUInt32(I);
      HashInstance.Calc(Count, SizeOf(Count));
      HashInstance.Calc(Result[0], I);

      HashInstance.Calc(Index, SizeOf(Index));

      Count := SwapUInt32(SeedSize);
      HashInstance.Calc(Count, SizeOf(Count));
      HashInstance.Calc(Seed, SeedSize);

      Count := SwapUInt32(DataSize);
      HashInstance.Calc(Count, SizeOf(Count));
      HashInstance.Calc(Data, DataSize);

      HashInstance.Done;

      R := 0;

      for J := 0 to DigestSize - 1 do
        R := R xor HashInstance.Digest[J];

      Result[I] := R;
    end;
  finally
    HashInstance.Free;
  end;
end;

class function TDECHashAuthentication.KDFx(const Data, Seed: TBytes;
                                           MaskSize: Integer;
                                           Index: UInt32 = 1): TBytes;
begin
  if (length(Seed) > 0) then
    Result := KDFx(Data[0], Length(Data), Seed[0], Length(Seed), MaskSize, Index)
  else
    Result := KDFx(Data[0], Length(Data), NullStr, Length(Seed), MaskSize, Index)
end;

class function TDECHashAuthentication.MGFx(const Data; DataSize, MaskSize: Integer;
                                           Index: UInt32 = 1): TBytes;
begin
  Result := KDFx(Data, DataSize, NullStr, 0, MaskSize, Index);
end;

class function TDECHashAuthentication.MGFx(const Data: TBytes;
                                           MaskSize: Integer;
                                           Index: UInt32 = 1): TBytes;
begin
  Result := KDFx(Data[0], Length(Data), NullStr, 0, MaskSize, Index);
end;

class function TDECHashAuthentication.HMAC(const Key, Text: RawByteString): TBytes;
begin
  result := HMAC(BytesOf(Key), BytesOf(Text));
end;

class function TDECHashAuthentication.HMAC(const Key, Text: TBytes): TBytes;
const
  CONST_UINT_OF_0x36 = $3636363636363636;
  CONST_UINT_OF_0x5C = $5C5C5C5C5C5C5C5C;
var
  HashInstance: TDECHashAuthentication;
  InnerKeyPad, OuterKeyPad: array of Byte;
  I, KeyLength, BlockSize, DigestLength: Integer;
begin
  HashInstance := TDECHashAuthenticationClass(self).Create;
  try
    BlockSize    := HashInstance.BlockSize; // 64 for sha1, ...
    DigestLength := HashInstance.DigestSize;
    KeyLength    := Length(Key);

    SetLength(InnerKeyPad, BlockSize);
    SetLength(OuterKeyPad, BlockSize);

    I := 0;

    if KeyLength > BlockSize then
    begin
      Result    := HashInstance.CalcBytes(Key);
      KeyLength := DigestLength;
    end
    else
      Result := Key;

    while I <= KeyLength - SizeOf(NativeUInt) do
    begin
      PNativeUInt(@InnerKeyPad[I])^ := PNativeUInt(@Result[I])^ xor NativeUInt(CONST_UINT_OF_0x36);
      PNativeUInt(@OuterKeyPad[I])^ := PNativeUInt(@Result[I])^ xor NativeUInt(CONST_UINT_OF_0x5C);
      Inc(I, SizeOf(NativeUInt));
    end;

    while I < KeyLength do
    begin
      InnerKeyPad[I] := Result[I] xor $36;
      OuterKeyPad[I] := Result[I] xor $5C;
      Inc(I);
    end;

    while I <= BlockSize - SizeOf(NativeUInt) do
    begin
      PNativeUInt(@InnerKeyPad[I])^ := NativeUInt(CONST_UINT_OF_0x36);
      PNativeUInt(@OuterKeyPad[I])^ := NativeUInt(CONST_UINT_OF_0x5C);
      Inc(I, SizeOf(NativeUInt));
    end;

    while I < BlockSize do
    begin
      InnerKeyPad[I] := $36;
      OuterKeyPad[I] := $5C;
      Inc(I);
    end;

    HashInstance.Init;
    HashInstance.Calc(InnerKeyPad[0], BlockSize);
    if Length(Text) > 0 then
      HashInstance.Calc(Text[0], Length(Text));
    HashInstance.Done;
    Result := HashInstance.DigestAsBytes;

    HashInstance.Init;
    HashInstance.Calc(OuterKeyPad[0], BlockSize);
    HashInstance.Calc(Result[0], DigestLength);
    HashInstance.Done;

    Result := HashInstance.DigestAsBytes;
  finally
    HashInstance.Free;
  end;
end;

class function TDECHashAuthentication.PBKDF2(const Password, Salt: TBytes; Iterations: Integer; KeyLength: Integer): TBytes;
const
  CONST_UINT_OF_0x36 = $3636363636363636;
  CONST_UINT_OF_0x5C = $5C5C5C5C5C5C5C5C;
var
  Hash: TDECHashAuthentication;
  I, J, C: Integer;
  BlockCount, HashLengthRounded, SaltLength: Integer;
  PassLength, DigestLength, BlockSize: Integer;
  InnerKeyPad, OuterKeyPad: TBytes;
  SaltEx, T, U, TrimmedKey: TBytes;
begin
  SetLength(Result, 0);
  Hash := TDECHashAuthenticationClass(self).Create;
  try
    // Setup needed parameters
    DigestLength      := Hash.DigestSize;
    HashLengthRounded := DigestLength - SizeOf(NativeUInt) + 1;
    BlockCount        := Trunc((KeyLength + DigestLength - 1) / DigestLength);
    BlockSize         := Hash.BlockSize;
    PassLength        := Length(Password);
    SaltLength        := Length(Salt);
    SaltEx            := Salt;
    SetLength(SaltEx, SaltLength + 4);  // reserve 4 bytes for INT_32_BE(i)
    SetLength(T, DigestLength);

    // Prepare Key for HMAC calculation
    // PrepareKeyForHMAC;
    I := 0;
    if (PassLength > BlockSize) then
    begin
      TrimmedKey := Hash.CalcBytes(Password);
      PassLength := DigestLength;
    end
    else
      TrimmedKey := Password;

    SetLength(InnerKeyPad, BlockSize);
    SetLength(OuterKeyPad, BlockSize);
    while (I < PassLength) do
    begin
      InnerKeyPad[I] := TrimmedKey[I] xor $36;
      OuterKeyPad[I] := TrimmedKey[I] xor $5C;
      Inc(I);
    end;

    while (I < BlockSize) do
    begin
      InnerKeyPad[I] := $36;
      OuterKeyPad[I] := $5C;
      Inc(I);
    end;

    // Calculate DK
    for I := 1 to BlockCount do
    begin
      SaltEx[SaltLength + 0] := Byte(I shr 24);   // INT_32_BE(i)
      SaltEx[SaltLength + 1] := Byte(I shr 16);
      SaltEx[SaltLength + 2] := Byte(I shr 8);
      SaltEx[SaltLength + 3] := Byte(I shr 0);
      FillChar(T[0], DigestLength, 0);            // reset Ti / F
      U := SaltEx;                                // initialize U to U1 = Salt + INT_32_BE(i)
      // Calculate F(Password, Salt, c, i) = U1 ^ U2 ^ ... ^ Uc
      for C := 1 to Iterations do
      begin
        Hash.Init;
        Hash.Calc(InnerKeyPad[0], BlockSize);
        Hash.Calc(U[0], Length(U));
        Hash.Done;
        U := Hash.DigestAsBytes;

        Hash.Init;
        Hash.Calc(OuterKeyPad[0], BlockSize);
        Hash.Calc(U[0], DigestLength);
        Hash.Done;
        U := Hash.DigestAsBytes;                  // Ui
        // F = U1 ^ U2 ^ ... ^ Uc
        J := 0;
        while (J < HashLengthRounded) do
        begin
          PNativeUInt(@T[J])^ := PNativeUInt(@T[J])^ xor PNativeUInt(@U[J])^;
          Inc(J, SizeOf(NativeUInt));
        end;

        while (J < DigestLength) do
        begin
          T[J] := T[J] xor U[J];
          Inc(J);
        end;
      end;

      if (I = 1) then
        Result := Copy(T)
      else
        Result := Result + T;  // DK += F    , DK = DK || Ti
    end;
  finally
    Hash.Free;
  end;

  // Trim to the needed key length
  SetLength(Result, KeyLength);
end;

class function TDECHashAuthentication.PBKDF2(const Password, Salt: RawByteString; Iterations: Integer; KeyLength: Integer): TBytes;
begin
  Result := PBKDF2(BytesOf(Password), BytesOf(Salt), Iterations, KeyLength);
end;

{ TDECHashExtended }

procedure TDECHashExtended.CalcStream(const Stream: TStream; Size: Int64;
  var HashResult: TBytes; const OnProgress:TDECProgressEvent);
var
  Buffer: TBytes;
  Bytes: Integer;
  Max, Pos: Int64;
begin
  Assert(Assigned(Stream), 'Stream to calculate hash on is not assigned');

  Max := 0;
  SetLength(HashResult, 0);
  try
    Init;

    if StreamBufferSize <= 0 then
      StreamBufferSize := 8192;

    Pos := Stream.Position;

    if Size < 0 then
      Size := Stream.Size - Pos;

    // Last byte is incomplete so it mustn't be processed
    if (FFinalByteLength > 0) then
      Dec(Size);

    Max      := Pos + Size;

    if Assigned(OnProgress) then
      OnProgress(Max, 0, Started);

    Bytes := StreamBufferSize mod FBufferSize;

    if Bytes = 0 then
      Bytes := StreamBufferSize
    else
      Bytes := StreamBufferSize + FBufferSize - Bytes;

    if Bytes > Size then
      SetLength(Buffer, Size)
    else
      SetLength(Buffer, Bytes);

    while Size > 0 do
    begin
      Bytes := Length(Buffer);
      if Bytes > Size then
        Bytes := Size;
      Stream.ReadBuffer(Buffer[0], Bytes);
      Calc(Buffer[0], Bytes);
      Dec(Size, Bytes);
      Inc(Pos, Bytes);

      if Assigned(OnProgress) then
        OnProgress(Max, Pos, Processing);
    end;

    // Last byte is incomplete but algorithm may need its value for padding
    if (FFinalByteLength > 0) then
      Stream.ReadBuffer(FPaddingByte, 1);

    Done;
    HashResult := DigestAsBytes;
  finally
    ProtectBytes(Buffer);
    if Assigned(OnProgress) then
      OnProgress(Max, Max, Finished);
  end;
end;

function TDECHashExtended.CalcStream(const Stream: TStream; Size: Int64;
  Format: TDECFormatClass; const OnProgress:TDECProgressEvent): RawByteString;
var
  Hash: TBytes;
begin
  CalcStream(Stream, Size, Hash, OnProgress);
  Result := BytesToRawString(ValidFormat(Format).Encode(Hash));
end;

procedure TDECHashExtended.CalcStream(const Stream: TStream; Size: Int64;
                              const OnProgress:TDECProgressEvent;
                              DoFinalize: Boolean);
var
  Buffer: TBytes;
  Bytes: Integer;
  Max, Pos: Int64;
begin
  Assert(Assigned(Stream), 'Stream to calculate hash on is not assigned');

  Max := 0;
  try
    if StreamBufferSize <= 0 then
      StreamBufferSize := 8192;

    Pos := Stream.Position;

    if Size < 0 then
      Size := Stream.Size - Pos;

    // Last byte is incomplete so it mustn't be processed
    if DoFinalize and (FFinalByteLength > 0) then
      Dec(Size);

    Max      := Pos + Size;

    if Assigned(OnProgress) then
      OnProgress(Max, 0, Started);

    Bytes := StreamBufferSize mod FBufferSize;

    if Bytes = 0 then
      Bytes := StreamBufferSize
    else
      Bytes := StreamBufferSize + FBufferSize - Bytes;

    if Bytes > Size then
      SetLength(Buffer, Size)
    else
      SetLength(Buffer, Bytes);

    while Size > 0 do
    begin
      Bytes := Length(Buffer);
      if Bytes > Size then
        Bytes := Size;
      Stream.ReadBuffer(Buffer[0], Bytes);
      Calc(Buffer[0], Bytes);
      Dec(Size, Bytes);
      Inc(Pos, Bytes);

      if Assigned(OnProgress) then
        OnProgress(Max, Pos, Processing);
    end;

    // Last byte is incomplete but algorithm may need its value for padding
    if DoFinalize then
    begin
      if (FFinalByteLength > 0) then
        Stream.ReadBuffer(FPaddingByte, 1);
      Done;
    end;
  finally
    ProtectBytes(Buffer);
    if Assigned(OnProgress) then
      OnProgress(Max, Max, Finished);
  end;
end;

procedure TDECHashExtended.CalcFile(const FileName: string; var HashResult: TBytes;
                            const OnProgress:TDECProgressEvent);
var
  S: TFileStream;
begin
  SetLength(HashResult, 0);
  S := TFileStream.Create(FileName, fmOpenRead or fmShareDenyNone);
  try
    CalcStream(S, S.Size, HashResult, OnProgress);
  finally
    S.Free;
  end;
end;

function TDECHashExtended.CalcFile(const FileName: string; Format: TDECFormatClass;
                           const OnProgress:TDECProgressEvent): RawByteString;
var
  Hash: TBytes;
begin
  CalcFile(FileName, Hash, OnProgress);
  Result := BytesToRawString(ValidFormat(Format).Encode(Hash));
end;

{ TArrHelper }

{$IFNDEF HAVE_ASSIGN_ARRAY}
class procedure TArrHelper.AppendArrays<T>(var A: TArray<T>; const B: TArray<T>);
var
  i, L: Integer;
begin
  L := Length(A);
  SetLength(A, L + Length(B));
  for i := 0 to High(B) do
    A[L + i] := B[i];
end;
{$ENDIF}

{ TDECPasswordHash }

function TDECPasswordHash.GetSalt: TBytes;
begin
  Result := FSalt;
end;

procedure TDECPasswordHash.SetSalt(const Value: TBytes);
begin
  if (Length(Value) > MaxSaltLength) then
    raise EDECHashException.CreateFmt(sSaltValueTooLong, [MaxSaltLength]);

  if (Length(Value) < MinSaltLength) then
    raise EDECHashException.CreateFmt(sSaltValueTooShort, [MinSaltLength]);

  FSalt := Value;
end;

class function TDECPasswordHash.GetCryptID: string;
begin
  Result := '';
end;

function TDECPasswordHash.GetCryptParams(const Params : string;
                                         Format       : TDECFormatClass): string;
begin
  Result := '';
end;

function TDECPasswordHash.GetCryptSalt(const Salt : TBytes;
                                       Format     : TDECFormatCLass): string;
var
  FormattedSalt : TBytes;
begin
  FormattedSalt := Format.Encode(Salt);

  Result := '$' + TEncoding.ASCII.GetString(FormattedSalt);
end;

class function TDECPasswordHash.ClassByCryptIdentity(
  Identity: string): TDECPasswordHashClass;
var
  ClassEntry : TClassListEntry;
  IDLower    : string;
begin
  IDLower := Identity.ToLower;
  if not IDLower.StartsWith('$') then
    IDLower := '$' + IDLower;

  for ClassEntry in ClassList do
  begin
    if TDECHashClass(ClassEntry.Value).IsPasswordHash and
       (string(TDECPasswordHashClass(ClassEntry.Value).GetCryptID).ToLower = IDLower)  then
    begin
      Result := TDECPasswordHashClass(ClassEntry.Value);
      Exit;
    end;
  end;

  // If we got this far, we have not found any mathich class
  raise EDECClassNotRegisteredException.CreateResFmt(@sCryptIDNotRegistered,
                                                     [Identity]);
end;

procedure TDECPasswordHash.DoDone;
begin
  inherited;

  ProtectBuffer(FSalt[0], SizeOf(FSalt));
  SetLength(FSalt, 0);
end;

function TDECPasswordHash.GetCryptHash(Password     : TBytes;
                                       const Params : string;
                                       const Salt   : TBytes;
                                       Format       : TDECFormatClass): string;
begin
  Result := '';
end;

function TDECPasswordHash.GetDigestInCryptFormat(
                            const Password : string;
                            const Params   : string;
                            const Salt     : string;
                            SaltIsRaw      : Boolean;
                            Format         : TDECFormatClass): string;
begin
  Result := GetDigestInCryptFormat(TEncoding.UTF8.GetBytes(Password),
                                   Params,
                                   Salt,
                                   SaltIsRaw,
                                   Format);
end;

function TDECPasswordHash.GetDigestInCryptFormat(
                            Password     : TBytes;
                            const Params : string;
                            const Salt   : string;
                            SaltIsRaw    : Boolean;
                            Format       : TDECFormatClass): string;
var
  SaltBytes : TBytes;
begin
  // generic format used by Crypt, but not every algorithm sticks 100% to it
  // $<id>[$<param>=<value>(,<param>=<value>)*][$<salt>[$<hash>]]

  // if no ID is delivered the algorithm is none of the Crypt/BSD algorithms
  Result := GetCryptID;
  if (Result <> '') then
  begin
    if SaltIsRaw then
      SaltBytes := TEncoding.UTF8.GetBytes(Salt)
    else
      SaltBytes := Format.Decode(TEncoding.UTF8.GetBytes(Salt));

    Result := Result + GetCryptParams(Params, Format) +
                       GetCryptSalt(SaltBytes, Format) +
                       GetCryptHash(Password, Params, SaltBytes, Format);
  end;
end;

function TDECPasswordHash.IsValidPassword(const Password  : string;
                                          const CryptData : string;
                                          Format          : TDECFormatClass): Boolean;
begin
  Result := IsValidPassword(TEncoding.UTF8.GetBytes(Password),
                            CryptData,
                            Format);
end;

function TDECPasswordHash.IsValidPassword(Password        : TBytes;
                                          const CryptData : string;
                                          Format          : TDECFormatClass): Boolean;
begin
  Result := false;
end;

function ValidAuthenticationHash(HashClass: TDECHashClass): TDECHashAuthenticationClass;
begin
  if Assigned(HashClass) then
    Result := TDECHashAuthenticationClass(HashClass)
  else
    Result := FDefaultAutheticationHashClass;

  if not Assigned(Result) then
    raise EDECHashException.CreateRes(@sAuthHashNoDefault);
end;

procedure SetDefaultAuthenticationHashClass(HashClass: TDECHashClass);
begin
  Assert(Assigned(HashClass), 'Do not set a nil default hash class!');

  FDefaultAutheticationHashClass := TDECHashAuthenticationClass(HashClass);
end;

end.
