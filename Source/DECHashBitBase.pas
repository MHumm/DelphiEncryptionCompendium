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
///   Base unit for all the hash algorithms which can operate on bit sized
///   messsages as well.
/// </summary>
unit DECHashBitBase;

interface

{$INCLUDE DECOptions.inc}

uses
  {$IFDEF FPC}
  SysUtils, Classes,
  {$ELSE}
  System.SysUtils, System.Classes,
  {$ENDIF}
  DECHashAuthentication, DECFormatBase, DECUtil;

type
  /// <summary>
  ///   Base class for all hash algorithms which can operate on bit sized
  ///   messsages as well.
  /// </summary>
  TDECHashBit = class(TDECHashAuthentication)
  strict protected
    /// <summary>
    ///   Processes one chunk of data to be hashed.
    /// </summary>
    /// <param name="Data">
    ///   Data on which the hash value shall be calculated on
    /// </param>
    /// <param name="DataSizeInBits">
    ///   Size of the data in bits
    /// </param>
    procedure CalcBits(const Data; DataSizeInBits: UInt32); virtual; abstract;
  public
    /// <summary>
    ///   Calculates the hash value (digest) for a given buffer
    /// </summary>
    /// <param name="Buffer">
    ///   Untyped buffer the hash shall be calculated for
    /// </param>
    /// <param name="DataSizeInBits">
    ///   Size of the buffer in bit
    /// </param>
    /// <returns>
    ///   Byte array with the calculated hash value
    /// </returns>
    function CalcBufferBits(const Buffer; DataSizeInBits: UInt32): TBytes;
    /// <summary>
    ///   Calculates the hash value (digest) for a given buffer. Raises
    ///   a EDECHashException when size of Data in bit is less than DataSizeInBits
    /// </summary>
    /// <param name="Data">
    ///   The TBytes array the hash shall be calculated on
    /// </param>
    /// <param name="DataSizeInBits">
    ///   Number of bits from the beginning of data over which the hash value
    ///   will be calculated
    /// </param>
    /// <returns>
    ///   Byte array with the calculated hash value
    /// </returns>
    function CalcBytesBits(const Data: TBytes; DataSizeInBits: UInt32): TBytes;
    /// <summary>
    ///   Calculates the hash value (digest) for a given rawbytestring. Raises
    ///   a EDECHashException when size of Value in bit is less than DataSizeInBits
    /// </summary>
    /// <param name="Value">
    ///   The string the hash shall be calculated on
    /// </param>
    /// <param name="DataSizeInBits">
    ///   Number of bits from the beginning of the string over which the hash
    ///   value will be calculated
    /// </param>
    /// <param name="Format">
    ///   Formatting class from DECFormat. The formatting will be applied to the
    ///   returned digest value. This parameter is optional.
    /// </param>
    /// <returns>
    ///   string with the calculated hash value
    /// </returns>
    function CalcStringBits(const Value: RawByteString; DataSizeInBits: UInt32;
                            Format: TDECFormatClass): RawByteString; overload;

    /// <summary>
    ///   Calculates the hash value over a given stream of bytes. Raises
    ///   a EDECHashException when size of the stream in bit from the current
    ///   position to its end is less than DataSizeInBits.
    /// </summary>
    /// <param name="Stream">
    ///   Memory or file stream over which the hash value shall be calculated.
    ///   The stream must be assigned. The hash value will always be calculated
    ///   from the current position of the stream.
    /// </param>
    /// <param name="DataSizeInBits">
    ///   Number of bits from the current position of the stream over which the
    ///   hash value will be calculated.
    /// </param>
    /// <param name="HashResult">
    ///   In this byte array the calculated hash value will be returned.
    /// </param>
    /// <param name="OnProgress">
    ///   Optional callback routine. It can be used to display the progress of
    ///   the operation.
    /// </param>
    procedure CalcStreamBits(const Stream: TStream; DataSizeInBits: Int64;
                             var HashResult: TBytes;
                             const OnProgress:TDECProgressEvent = nil); overload;
    /// <summary>
    ///   Calculates the hash value over a givens stream of bytes. Raises
    ///   a EDECHashException when size of the stream in bit from the current
    ///   position to its end is less than DataSizeInBits.
    /// </summary>
    /// <param name="Stream">
    ///   Memory or file stream over which the hash value shall be calculated.
    ///   The stream must be assigned. The hash value will always be calculated
    ///   from the current position of the stream.
    /// </param>
    /// <param name="DataSizeInBits">
    ///   Number of bits from the current position of the stream over which the
    ///   hash value will be calculated.
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
    function CalcStreamBits(const Stream: TStream; DataSizeInBits: Int64;
                            Format: TDECFormatClass = nil;
                            const OnProgress:TDECProgressEvent = nil): RawByteString; overload;
  end;

implementation

resourcestring
  /// <summary>
  ///   Exception message text used when data is passed which is shorter than
  ///   the bit lengtgh specified
  /// </summary>
  sDataDoesNotMatchBitlength = 'Data given is shorter than bitlength given' + sLineBreak +
                               'Databits: %0:d Bitlength: %1:d';

{ TDECHashBit }

function TDECHashBit.CalcBufferBits(const Buffer; DataSizeInBits: UInt32): TBytes;
begin
  Init;
  CalcBits(Buffer, DataSizeInBits);
  Done;
  Result := DigestAsBytes;
end;

function TDECHashBit.CalcBytesBits(const Data: TBytes; DataSizeInBits: UInt32): TBytes;
begin
  if (UInt32(Length(Data)*8) < DataSizeInBits) then
    raise EDECHashException.CreateFmt(sDataDoesNotMatchBitlength,
                                      [Length(Data)*8, DataSizeInBits]);

  SetLength(Result, 0);
  if Length(Data) > 0 then
    Result := CalcBuffer(Data[0], DataSizeInBits)
  else
    Result := CalcBuffer(Data, DataSizeInBits);
end;

function TDECHashBit.CalcStreamBits(const Stream     : TStream;
                                    DataSizeInBits   : Int64;
                                    Format           : TDECFormatClass;
                                    const OnProgress : TDECProgressEvent): RawByteString;
var
  Hash: TBytes;
begin
  CalcStreamBits(Stream, DataSizeInBits, Hash, OnProgress);
  Result := BytesToRawString(ValidFormat(Format).Encode(Hash));
end;

procedure TDECHashBit.CalcStreamBits(const Stream     : TStream;
                                     DataSizeInBits   : Int64;
                                     var HashResult   : TBytes;
                                     const OnProgress : TDECProgressEvent);
begin
{ TODO :
Implementing similar to DECHashBase but extend it so that
it takes into account that DataSizeInBits here is Int64 while
in CalcBufferBits it is UInt32... }
  raise EProgrammerNotFound.Create('Implementation missing!');
end;

function TDECHashBit.CalcStringBits(const Value: RawByteString;
  DataSizeInBits: UInt32; Format: TDECFormatClass): RawByteString;
var
  Buf : TBytes;
begin
  if (UInt32(Length(Value)*8) < DataSizeInBits) then
    raise EDECHashException.CreateFmt(sDataDoesNotMatchBitlength,
                                      [Length(Value)*8, DataSizeInBits]);

  Result := '';
  if Length(Value) > 0 then
    {$IF CompilerVersion >= 17.0}
    result := BytesToRawString(
                ValidFormat(Format).Encode(
                  CalcBufferBits(Value[low(Value)], DataSizeInBits)))
    {$ELSE}
    result := BytesToRawString(
                ValidFormat(Format).Encode(
                  CalcBufferBits(Value[1], DataSizeInBits)))
    {$ENDIF}
  else
  begin
    SetLength(Buf, 0);
    Result := BytesToRawString(ValidFormat(Format).Encode(CalcBufferBits(Buf, 0)));
  end;
end;

end.
