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
unit DECAuthenticatedCipherModesBase;

interface

{$INCLUDE DECOptions.inc}

uses
  {$IFDEF FPC}
  SysUtils,
  {$ELSE}
  System.SysUtils,
  {$ENDIF}
  DECTypes;

type
  /// <summary>
  ///   Exception raised when nonce has a wrong length
  /// </summary>
  EDECNonceLengthException = class(EDECException);
  /// <summary>
  ///   Exception raised when authentication value has wrong length
  /// </summary>
  EDECAuthLengthException  = class(EDECException);

  /// <summary>
  ///   A method of this type needs to be supplied for encrypting or decrypting
  ///   a block via an authenticated cipher mode. The method is implemented as a
  ///   parameter to allow composition instead of inheritance (e.g. TGCM/TCCM
  ///   hold a reference to the underlying block cipher's encode method).
  /// </summary>
  /// <param name="Source">
  ///   Data to be encrypted
  /// </param>
  /// <param name="Dest">
  ///   In this memory the encrypted result will be written
  /// </param>
  /// <param name="Size">
  ///   Size of source in byte
  /// </param>
  TEncodeDecodeMethod = procedure(Source, Dest: Pointer; Size: Integer) of Object;

  /// <summary>
  ///   Base class for authenticated cipher modes (GCM, CCM, future AEAD modes).
  /// </summary>
  /// <remarks>
  ///   Lifecycle for multi-call capable modes (e.g. GCM):
  ///   <para>
  ///     Init → set AAD / tag length / expected tag → Encode/Decode* → Done →
  ///     read CalculatedAuthenticationTag.
  ///   </para>
  ///   <para>
  ///     Done must be called before the calculated authentication tag is valid
  ///     for multi-call streams. Done is idempotent. After Done, further
  ///     Encode/Decode raises until Init is called again.
  ///   </para>
  ///   <para>
  ///     CCM remains one-shot (single Encode/Decode with full message length);
  ///     Done still verifies ExpectedAuthenticationTag when set.
  ///   </para>
  /// </remarks>
  TAuthenticatedCipherModesBase = class(TObject)
  strict protected
    /// <summary>
    ///   The data which shall be authenticated in parallel to the encryption
    /// </summary>
    FDataToAuthenticate          : TBytes;
    /// <summary>
    ///   Length of the authentication tag to generate in byte
    /// </summary>
    FCalcAuthenticationTagLength : UInt32;
    /// <summary>
    ///   Generated authentication tag
    /// </summary>
    FCalcAuthenticationTag       : TBytes;

    /// <summary>
    ///   Expected authentication tag value, will be compared with actual value
    ///   when decryption finished.
    /// </summary>
    FExpectedAuthenticationTag   : TBytes;

    /// <summary>
    ///   Reference to the encode method of the actual cipher used
    /// </summary>
    FEncryptionMethod            : TEncodeDecodeMethod;

    /// <summary>
    ///   Defines the length of the resulting authentication value in bit.
    /// </summary>
    /// <param name="Value">
    ///   Sets the length of Authenticaton_tag in bit, values as per specification
    ///   of the concrete algorithm implemented in a child class
    /// </param>
    procedure SetAuthenticationTagLength(const Value: UInt32); virtual;
    /// <summary>
    ///   Returns the length of the calculated authentication value in bit
    /// </summary>
    /// <returns>
    ///   Length of the calculated authentication value in bit
    /// </returns>
    function GetAuthenticationTagBitLength: UInt32; virtual;
  public
    /// <summary>
    ///   Should be called when starting encryption/decryption in order to
    ///   initialize internal tables etc.
    /// </summary>
    /// <param name="EncryptionMethod">
    ///   Encryption method of the cypher used
    /// </param>
    /// <param name="InitVector">
    ///   Initialization vector
    /// </param>
    procedure Init(EncryptionMethod : TEncodeDecodeMethod;
                   InitVector       : TBytes); virtual;

    /// <summary>
    ///   Encodes a block of data using the supplied cipher. May be called
    ///   multiple times for modes that support streaming (e.g. GCM).
    /// </summary>
    /// <param name="Source">
    ///   Plain text to encrypt
    /// </param>
    /// <param name="Dest">
    ///   Ciphertext after encryption
    /// </param>
    /// <param name="Size">
    ///   Number of bytes to encrypt
    /// </param>
    procedure Encode(Source,
                     Dest   : PUInt8Array;
                     Size   : Integer); virtual; abstract;
    /// <summary>
    ///   Decodes a block of data using the supplied cipher. May be called
    ///   multiple times for modes that support streaming (e.g. GCM).
    /// </summary>
    /// <param name="Source">
    ///   Encrypted ciphertext to decrypt
    /// </param>
    /// <param name="Dest">
    ///   Plaintext after decryption
    /// </param>
    /// <param name="Size">
    ///   Number of bytes to decrypt
    /// </param>
    procedure Decode(Source,
                     Dest   : PUInt8Array;
                     Size   : Integer); virtual; abstract;

    /// <summary>
    ///   Finalizes the authentication tag after all Encode/Decode calls.
    ///   Idempotent. Default implementation is a no-op (suitable for modes that
    ///   already compute the tag inside Encode/Decode, e.g. CCM).
    /// </summary>
    procedure Done; virtual;

    /// <summary>
    ///   Returns a list of authentication tag lengths explicitely specified by
    ///   the official specification of the standard.
    /// </summary>
    /// <returns>
    ///   List of bit lengths
    /// </returns>
    function GetStandardAuthenticationTagBitLengths:TStandardBitLengths; virtual;

    /// <summary>
    ///   The data which shall be authenticated in parallel to the encryption
    /// </summary>
    property DataToAuthenticate : TBytes
      read   FDataToAuthenticate
      write  FDataToAuthenticate;
    /// <summary>
    ///   Sets the length of AuthenticatonTag in bit, values as per official
    ///   specification are: 128, 120, 112, 104, or 96 bit. For certain
    ///   applications, they may be 64 or 32 as well, but the use of these two
    ///   tag lengths constrains the length of the input data and the lifetime
    ///   of the key.
    /// </summary>
    property AuthenticationTagBitLength : UInt32
      read   GetAuthenticationTagBitLength
      write  SetAuthenticationTagLength;
    /// <summary>
    ///   Calculated authentication value. For multi-call modes this is only
    ///   complete after Done has been called.
    /// </summary>
    property CalculatedAuthenticationTag : TBytes
      read   FCalcAuthenticationTag
      write  FCalcAuthenticationTag;

    /// <summary>
    ///   Expected authentication tag value, will be compared with actual value
    ///   when decryption finished.
    /// </summary>
    property ExpectedAuthenticationTag : TBytes
      read   FExpectedAuthenticationTag
      write  FExpectedAuthenticationTag;
  end;

implementation

uses
  DECUtil;

{ TAuthenticatedCipherModesBase }

function TAuthenticatedCipherModesBase.GetAuthenticationTagBitLength: UInt32;
begin
  Result := FCalcAuthenticationTagLength shl 3;
end;

function TAuthenticatedCipherModesBase.GetStandardAuthenticationTagBitLengths: TStandardBitLengths;
begin
  SetLength(Result, 0);
end;

procedure TAuthenticatedCipherModesBase.Init(EncryptionMethod : TEncodeDecodeMethod;
                                             InitVector       : TBytes);
var
  CalcAuthLength : Integer;
begin
  Assert(Assigned(EncryptionMethod), 'No encryption method specified');

  // Clear calculated authentication value
  CalcAuthLength := Length(FCalcAuthenticationTag);
  if (CalcAuthLength > 0) then
  begin
    ProtectBytes(FCalcAuthenticationTag);
    SetLength(FCalcAuthenticationTag, CalcAuthLength);
    FillChar(FCalcAuthenticationTag[0], CalcAuthLength, #0);
  end;

  FEncryptionMethod := EncryptionMethod;
end;

procedure TAuthenticatedCipherModesBase.Done;
begin
  // Default: no deferred finalization (CCM computes the tag in Encode/Decode).
  // Streaming modes such as GCM override this to materialize the tag.
end;

procedure TAuthenticatedCipherModesBase.SetAuthenticationTagLength(const Value: UInt32);
begin
  FCalcAuthenticationTagLength := Value shr 3;
  SetLength(FCalcAuthenticationTag, FCalcAuthenticationTagLength);
end;

end.
