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
///   x86 and x64 CPU instruction support functions.
///   this class only works for intel cpus - arm will result.
///   The functions defined here return true if the feature is availabe
///   for the cpu
/// </summary>

unit DECCPUSupport;

interface

type
  TDEC_CPUSupport = class(TObject)
  public
    // flags are set in initialization
    class var AES : boolean;
    class var AVX : boolean;
    class var AVX2 : boolean;

    class var SSE : boolean;
    class var SSE2 : boolean;
    class var SSE3 : boolean;
    class var SSE41 : boolean;
    class var SSE42 : boolean;

    class var RDRand : boolean;
    class var RDSeed : boolean;
  end;

implementation

{$IFDEF CPUX64}
{$DEFINE x64}
{$ENDIF}
{$IFDEF cpux86_64}
{$DEFINE x64}
{$ENDIF}

{$IFDEF CPU86}
{$DEFINE x86}
{$ENDIF}
{$IFDEF CPUX86}
{$DEFINE x86}
{$ENDIF}

{$IFDEF CPU386}
{$DEFINE x86}
{$ENDIF}


{$IF Defined(x64) or Defined(x86)}
{$WARN SYMBOL_PLATFORM OFF}
procedure InitFlags;
var reg : TCPUIDRec;
    nids : LongWord;
begin
     reg := GetCPUID(0, 0);
     nids := reg.EAX;


     if nids >= 1 then
     begin
          reg := GetCPUID(1, 0);
          TDEC_CPUSupport.SSE := (reg.EDX and (1 shl 25)) <> 0;
          TDEC_CPUSupport.SSE2 := (reg.EDX and (1 shl 26)) <> 0;
          TDEC_CPUSupport.SSE3  := (reg.ECX and (1 shl 9)) <> 0;
          TDEC_CPUSupport.SSE41  := (reg.ECX and (1 shl 19)) <> 0;
          TDEC_CPUSupport.SSE42  := (reg.ECX and (1 shl 20)) <> 0;
          TDEC_CPUSupport.AES := (reg.ECX and (1 shl 25)) <> 0;

          TDEC_CPUSupport.AVX := (reg.ECX and (1 shl 28)) <> 0;
          TDEC_CPUSupport.RDRAND := (reg.ECX and (1 shl 30)) <> 0;
     end;

     if nids >= 7 then
     begin
          reg := GetCPUID($7);
          TDEC_CPUSupport.AVX2 := (reg.EBX and (1 shl 5)) <> 0;
          TDEC_CPUSupport.RDSEED := (reg.EBX and (1 shl  18)) <> 0;
     end;
end;
{$ENDIF}

initialization
    TDEC_CPUSupport.AES := False;
    TDEC_CPUSupport.AVX := False;
    TDEC_CPUSupport.AVX2 := False;

    TDEC_CPUSupport.SSE := False;
    TDEC_CPUSupport.SSE2 := False;
    TDEC_CPUSupport.SSE3 := False;
    TDEC_CPUSupport.SSE41 := False;
    TDEC_CPUSupport.SSE42 := False;

    TDEC_CPUSupport.RDRand := False;
    TDEC_CPUSupport.RDSeed := False;
{$IF Defined(x64) or Defined(x86)}
    InitFlags;
{$IFEND}
end.
