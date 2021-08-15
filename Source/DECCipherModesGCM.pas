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
unit DECCipherModesGCM;

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
  ///   128 bit unsigned integer
  /// </summary>
  T128 = array[0..1] of UInt64;
  /// <summary>
  ///   pointer to an 128 bit unsigned integer
  /// </summary>
  P128 = ^T128;

  /// <summary>
  ///   Galois Counter Mode specific methods
  /// </summary>
  TGCM = class(TObject)
  private
     nullbytes : T128;
     M         : array[0..15,0..255] of T128;

    /// <summary>
    ///   XOR implementation for unsigned 128 bit numbers
    /// </summary>
    /// <param name="x">
    ///   First number to xor
    /// </param>
    /// <param name="y">
    ///   Second number to xor the first with
    /// </param>
    /// <returns>
    ///   x xor y
    /// </returns>
    function XOR_128(const x, y: T128): T128; inline;
    /// <summary>
    ///   XOR implementation for a pointer and an unsigned 128 bit number
    /// </summary>
    /// <param name="x">
    ///   Pointer on a T128 typed number to xor with y
    /// </param>
    /// <param name="y">
    ///   Second number to xor the first with
    /// </param>
    /// <returns>
    ///   x xor y
    /// </returns>
    function XOR_128_n(const x : Pointer; y : T128 ) : T128; inline;
    /// <summary>
    ///   XORs the bytes given in a byte array with a T128 number given
    /// </summary>
    /// <param name="x">
    ///   Bytes which shall be XORed with the T128 number
    /// </param>
    /// <param name="XIndex">
    ///   Starting index within x from which onwards to XOR
    /// </param>
    /// <param name="len">
    ///   Number of bytes from x beginning at XIndex to XOR
    /// </param>
    /// <param name="y">
    ///   Value to XOR the bytes from y with. XOR is done bytewise for each
    ///   byte of y
    /// </param>
    /// <param name="res">
    ///   Result of the XOR operation
    /// </param>
    procedure XOR_128_n_l(const x : TBytes; XIndex, len : UInt64; y : T128; var res : TBytes ); inline;

    function poly_mult_H(const hx : T128) : T128; inline;
    procedure set_auth_Len_ciph_len(var x : T128; al, cl : UInt64); inline;
    procedure Table_M_8Bit(const H : T128); inline;
    procedure rightshift(var rx : T128); inline;
  public
  end;

implementation

function TGCM.XOR_128(const x, y : T128) : T128;
begin
  Result[0] := x[0] xor y[0];
  Result[1] := x[1] xor y[1];
end;

function TGCM.XOR_128_n(const x : Pointer; y : T128) : T128;
begin
  Result[0] := P128(x)^[0] xor y[0];
  Result[1] := P128(x)^[1] xor y[1];
end;

procedure TGCM.XOR_128_n_l(const x : TBytes; XIndex, len : UInt64; y : T128; var res : TBytes);
var
  i  : integer;
  { TODO : change to a pointer to y[0], to get rid of the absolute? }
  by : array[0..15] of byte absolute y[0];
begin
  for i := 0 to len-1 do
  begin
    res[XIndex] := x[XIndex] xor by[i];
    inc(XIndex);
  end;
end;

function TGCM.poly_mult_H(const hx : T128 ) : T128;
var
  i : integer;
  { TODO : change to a pointer to hx[0], to get rid of the absolute? }
  x : array[0..15] of byte absolute hx[0];
begin
  Result := M[0,x[0]];

  for i := 1 to 15 do
  begin
    Result[0] := Result[0] xor M[i,x[i]][0];
    Result[1] := Result[1] xor M[i,x[i]][1];
  end;
end;

procedure TGCM.set_auth_Len_ciph_len(var x : T128; al, cl : UInt64);
var
  i  : integer;
  { TODO : change to a pointer to x[0], to get rid of the absolute? }
  hx : array[0..15] of byte absolute x[0];
begin
  // al:
  x := nullbytes;
  i := 7;

  repeat
    hx[i] := al mod 256;
    al := al shr 8;
    dec(i);
  until al = 0;

  // cl:
  i := 15;

  repeat
    hx[i] := cl mod 256;
    cl := cl shr 8;
    dec(i);
  until cl = 0;
end;

procedure TGCM.Table_M_8Bit(const H : T128);
var
  hbit, hbyte, i, j : integer;
  HP : T128;
  { TODO : change to a pointer to HP[0], to get rid of the absolute? }
  bHP : array[0..15] of byte absolute HP[0];
  mask : byte;
begin
  HP := H;
  for hbyte := 0 to 15 do
  begin
    mask := 128;
    for hbit := 0 to 7 do
    begin
      M[hbyte,mask] := HP;

      if (bHP[15] and 1 = 0) then rightshift(HP) else
      begin
        rightshift(HP);
        bHP[0] := bHP[0] xor $e1;
      end;

      mask := mask shr 1;
    end;
  end;

  for hbyte := 0 to 15 do
  begin
    i := 2;
    while i <= 128 do
    begin
      for j := 1 to i-1 do
        M[hbyte,i+j] := XOR_128(M[hbyte,i], M[hbyte,j]);
      i := i*2;
    end;
    M[hbyte,0] := nullbytes;
  end;
end;

procedure TGCM.rightshift(var rx : T128);
var
  { TODO : change to a pointer to rx[0], to get rid of the absolute? }
  x : array[0..15] of byte absolute rx[0];
  i : integer;
begin
  for i := 15 downto 1 do
    x[i] := (x[i] shr 1) or ((x[i-1] and 1) shl 7);

  x[0] := x[0] shr 1;
end;


end.
