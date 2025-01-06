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
///   Declarations of various datatypes, some of those have not been
///   declared for certain platforms but are used in DEC and some do change
///   meanings between platforms like PLongWord where LongWord is 32 bit on
///   Windows and Android but 64 bit on iOS for instance
/// </summary>
unit DECTypes;

interface

{$INCLUDE DECOptions.inc}

uses
  {$IFDEF FPC}
  SysUtils;
  {$ELSE}
  System.SysUtils;
  {$ENDIF}

type
  /// <summary>
  ///   Replacement for PByteArray
  /// </summary>
  PUInt8Array = ^TInt8Array;
  TInt8Array = array[0..MaxInt-1] of Byte;

  PUInt32Array = ^TUInt32Array;
  TUInt32Array = array[0..1023] of UInt32;

  /// <summary>
  ///   Replacement for PLongWord, as LongWord changes between platforms from
  ///   32 to 64 bit
  /// </summary>
  PUInt32 = ^UINT32;

  PUInt64Array = ^TUInt64Array;
  TUInt64Array = array[0..1023] of UInt64;

  /// <summary>
  ///   Declared here because it is used by Blowfish cipher and BCrypt hash
  /// </summary>
  PBlowfish       = ^TBlowfishMatrix;
  TBlowfishMatrix = array[0..3, 0..255] of UInt32;
  TBlowfishKey    = array[0..17] of UInt32;

  /// <summary>
  ///   List of standard bit lengths defined in the official standard for some
  ///  algorithm property which allows a variable bit length.
  /// </summary>
  TStandardBitLengths = array of UInt16;

  /// <summary>
  ///   Reason for calling the progress event
  /// </summary>
  TDECProgressState = (Started, Processing, Finished);

  /// <summary>
  ///   Event type used by several hash- and cipher methods to display their
  ///   progress. It can be implemented as regular method, procedure and as
  ///   anonymous method, means: in place.
  /// </summary>
  /// <param name="Size">
  ///   Number of bytes to process. For files this is usually the file size. For
  ///   streams this can be less than the stream size if the stream is not being
  ///   processed from the beginning.
  /// </param>
  /// <param name="Pos">
  ///   Position within size in byte. For streams this may be a position
  ///   relative to the starting position for processing.
  /// </param>
  {$ifdef HAVE_LAMBDAS}
  TDECProgressEvent = reference to procedure(Size, Pos: Int64; State: TDECProgressState);
  {$else}
  TDECProgressEvent = procedure(Size, Pos: Int64; State: TDECProgressState);
  {$endif}

  // Exception Classes

  /// <summary>
  ///   Base exception class for all DEC specific exceptions,
  /// </summary>
  EDECException       = class(Exception)
  public
    {$IFDEF FMXTranslateableExceptions}
    /// <summary>
    ///   Creates the exception instance and makes the exception message translateable
    ///   via Firemonkey's TLang translation mechanism. Normal ressource strings
    ///   are not translated in the same way on mobile platforms as they are on
    ///   Win32/Win64.
    /// </summary>
    /// <param name="Msg">
    ///   String with a failure message to be output or logged
    /// </param>
    constructor Create(const Msg: string); reintroduce; overload;
    /// <summary>
    ///   Creates the exception instance and makes the exception message translateable
    ///   via Firemonkey's TLang translation mechanism. Normal ressource strings
    ///   are not translated in the same way on mobile platforms as they are on
    ///   Win32/Win64.
    /// </summary>
    /// <param name="Msg">
    ///   String with a failure message to be output or logged
    /// </param>
    /// <param name="Args">
    ///   Array with values for the parameters specified in the format string
    /// </param>
    constructor CreateFmt(const Msg: string;
                          const Args: array of const); reintroduce; overload;
    {$ENDIF}
  end;

  /// <summary>
  ///   Exception class used when reporting that a class searched in a list is
  ///   not contained in that list, e.g. when searching for a non existant
  ///   formatting class.
  /// </summary>
  EDECClassNotRegisteredException = class(EDECException);
  /// <summary>
  ///   Exception class for reporting formatting related exceptions
  /// </summary>
  EDECFormatException = class(EDECException);
  /// <summary>
  ///   Exception class for reporting exceptions related to hash functions
  /// </summary>
  EDECHashException   = class(EDECException);
  /// <summary>
  ///   Exception class for reporting encryption/decryption caused exceptions
  /// </summary>
  EDECCipherException = class(EDECException);
  /// <summary>
  ///   Exception class for reporting calculation of a wrong authentication
  ///   value when decrypting using a cipher supporting authentication
  /// </summary>
  EDECCipherAuthenticationException = class(EDECException);

  /// <summary>
  ///   Exception class for reporting the use of abstract things which cannot
  ///   be called directly
  /// </summary>
  EDECAbstractError = class(EDECException)
    /// <summary>
    ///   Create the exception using a meaningfull error message
    /// </summary>
    constructor Create(ClassName: string); overload;
  end;

const
{ TODO : Check why this is a constant, which is immediately used by the
         resource string. Is this because of the lack of resource string support
         of FMX on some platforms?}
  cAbstractError = 'Abstract Error: %s is not implemented';

resourcestring
  sAbstractError = cAbstractError;

implementation

{ EDECException }

{$IFDEF FMXTranslateableExceptions}
constructor EDECException.Create(const Msg: string);
begin
  inherited Create(Translate(msg));
end;

constructor EDECException.CreateFmt(const Msg: string;
                                    const Args: array of const);
begin
  inherited Create(Format(Translate(Msg), Args));
end;

constructor EDECAbstractError.Create(ClassName: string);
begin
  inherited Create(Format(Translate(sAbstractError), [ClassName]));
end;
{$ELSE}
constructor EDECAbstractError.Create(ClassName: string);
begin
  inherited CreateResFmt(@sAbstractError, [ClassName]);
end;
{$ENDIF}

end.
