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
  ///   Lifecycle for authenticated modes (GCM, CCM):
  ///   <para>
  ///     Init → set AAD / tag length / expected tag → Encode/Decode* → Done →
  ///     read CalculatedAuthenticationTag.
  ///   </para>
  ///   <para>
  ///     Done must be called before CalculatedAuthenticationTag may be read.
  ///     Reading the tag before Done raises EDECCipherException. Done is
  ///     idempotent. After Done, further Encode/Decode raises until Init is
  ///     called again.
  ///   </para>
  ///   <para>
  ///     GCM supports multi-call Encode/Decode without a pre-declared length.
  ///     CCM can process several Encode/Decode chunks if the total payload
  ///     length is known first (DeclarePayloadLength / one-shot Size).
  ///     The authentication tag is materialized in Done so both modes share
  ///     the same lifecycle.
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
    ///   True after Done has materialized the authentication tag. Reading
    ///   CalculatedAuthenticationTag before this is set raises. Encode/Decode
    ///   after finalization also raises until Init is called again.
    /// </summary>
    FFinalized                  : Boolean;

    /// <summary>
    ///   Defines the length of the resulting authentication value in bit.
    /// </summary>
    /// <param name="Value">
    ///   Sets the length of Authenticaton_tag in bit, values as per specification
    ///   of the concrete algorithm implemented in a child class
    /// </param>
    procedure SetAuthenticationTagLength(const Value: UInt32); virtual;
    /// <summary>
    ///   Assigns additional authenticated data (AAD). Modes may override to
    ///   reject changes after AAD has already been absorbed into the MAC state.
    /// </summary>
    procedure SetDataToAuthenticate(const Value: TBytes); virtual;
    /// <summary>
    ///   Returns the length of the calculated authentication value in bit
    /// </summary>
    /// <returns>
    ///   Length of the calculated authentication value in bit
    /// </returns>
    function GetAuthenticationTagBitLength: UInt32; virtual;
    /// <summary>
    ///   Returns the calculated authentication tag. Raises if Done has not
    ///   been called yet.
    /// </summary>
    /// <returns>
    ///   Calculated authentication tag bytes
    /// </returns>
    /// <exception cref="EDECCipherException">
    ///   Raised when the tag is read before Done.
    /// </exception>
    function GetCalculatedAuthenticationTag: TBytes; virtual;
    /// <summary>
    ///   Raises EDECCipherException when Encode/Decode is attempted after Done.
    /// </summary>
    /// <exception cref="EDECCipherException">
    ///   Raised when the mode has already been finalized.
    /// </exception>
    procedure CheckNotFinalized;
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
    ///   multiple times for modes that support streaming (e.g. GCM, CCM
    ///   with a declared payload length).
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
    ///   multiple times for modes that support streaming (e.g. GCM, CCM
    ///   with a declared payload length).
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
    ///   Idempotent. Marks the tag as readable via CalculatedAuthenticationTag.
    ///   Concrete modes that defer tag computation (GCM, CCM) override this
    ///   to materialize the tag before calling inherited.
    /// </summary>
    procedure Done; virtual;

    /// <summary>
    ///   True when Encode/Decode may be called more than once before Done.
    ///   GCM always supports this. CCM supports it when the total payload
    ///   length is known in advance (CCM is not an online AEAD: B_0 encodes
    ///   l(m); see RFC 3610 §1 and NIST SP 800-38C).
    /// </summary>
    /// <returns>
    ///   True if the mode can process the payload in several Encode/Decode calls
    /// </returns>
    function SupportsMultiChunk: Boolean; virtual;

    /// <summary>
    ///   Declares the total payload length in bytes. Required by CCM before
    ///   the first Encode/Decode when the message will be supplied in several
    ///   chunks. Ignored by GCM. For CCM, repeating the same length is
    ///   idempotent; a different length, a call after Encode/Decode has
    ///   started, or a call after Done raises EDECCipherException. One-shot
    ///   Encode/Decode still works without this: the first call's Size is
    ///   treated as the total.
    /// </summary>
    /// <param name="AByteLength">
    ///   Total plaintext/ciphertext length in bytes (not including the tag)
    /// </param>
    procedure DeclarePayloadLength(const AByteLength: UInt64); virtual;

    /// <summary>
    ///   Returns the payload length last declared via DeclarePayloadLength or
    ///   taken from a one-shot Encode/Decode. 0 if none.
    /// </summary>
    /// <returns>
    ///   Declared payload length in bytes
    /// </returns>
    function GetDeclaredPayloadLength: UInt64; virtual;

    /// <summary>
    ///   Returns a list of authentication tag lengths explicitely specified by
    ///   the official specification of the standard.
    /// </summary>
    /// <returns>
    ///   List of bit lengths prescribed by the mode specification. If the
    ///   mode does not prescribe any tag lengths, an empty array is returned.
    /// </returns>
    function GetStandardAuthenticationTagBitLengths:TStandardBitLengths; virtual;

    /// <summary>
    ///   The data which shall be authenticated in parallel to the encryption
    /// </summary>
    property DataToAuthenticate : TBytes
      read   FDataToAuthenticate
      write  SetDataToAuthenticate;
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
    ///   Calculated authentication value. Valid only after Done has been
    ///   called. Reading this property before Done raises EDECCipherException
    ///   so callers follow the Init → Encode/Decode* → Done → tag lifecycle.
    /// </summary>
    /// <exception cref="EDECCipherException">
    ///   Raised when the property is read before Done.
    /// </exception>
    property CalculatedAuthenticationTag : TBytes
      read   GetCalculatedAuthenticationTag
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

resourcestring
  sAuthenticationTagNotFinalized =
    'Calculated authentication tag is not available before Done has been called';
  sAuthenticatedModeAlreadyFinalized =
    'Authenticated cipher mode already finalized; call Init before further Encode/Decode';

{ TAuthenticatedCipherModesBase }

function TAuthenticatedCipherModesBase.GetAuthenticationTagBitLength: UInt32;
begin
  Result := FCalcAuthenticationTagLength shl 3;
end;

function TAuthenticatedCipherModesBase.GetCalculatedAuthenticationTag: TBytes;
begin
  if not FFinalized then
    raise EDECCipherException.CreateRes(@sAuthenticationTagNotFinalized);

  Result := FCalcAuthenticationTag;
end;

procedure TAuthenticatedCipherModesBase.CheckNotFinalized;
begin
  if FFinalized then
    raise EDECCipherException.CreateRes(@sAuthenticatedModeAlreadyFinalized);
end;

function TAuthenticatedCipherModesBase.GetStandardAuthenticationTagBitLengths: TStandardBitLengths;
begin
  // No prescribed lengths at this abstraction: return an empty array rather
  // than a dummy 0-entry so callers can distinguish "none specified" from a
  // specified length of 0 bits.
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
  FFinalized := False;
end;

procedure TAuthenticatedCipherModesBase.Done;
begin
  FFinalized := True;
end;

function TAuthenticatedCipherModesBase.SupportsMultiChunk: Boolean;
begin
  Result := False;
end;

procedure TAuthenticatedCipherModesBase.DeclarePayloadLength(const AByteLength: UInt64);
begin
  // Default: GCM and other online AEADs ignore a pre-declared length.
end;

function TAuthenticatedCipherModesBase.GetDeclaredPayloadLength: UInt64;
begin
  Result := 0;
end;

procedure TAuthenticatedCipherModesBase.SetAuthenticationTagLength(const Value: UInt32);
begin
  FCalcAuthenticationTagLength := Value shr 3;
  SetLength(FCalcAuthenticationTag, FCalcAuthenticationTagLength);
end;

procedure TAuthenticatedCipherModesBase.SetDataToAuthenticate(const Value: TBytes);
begin
  FDataToAuthenticate := Value;
end;

end.
