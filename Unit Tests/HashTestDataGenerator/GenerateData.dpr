{*****************************************************************************
  The DEC team (see file NOTICE.txt) licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License. A copy of this licence is found in the root directory of
  this project in the file LICENCE.txt or alternatively at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing,
  software distributed under the License is distributed on an
  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  KIND, either express or implied.  See the License for the
  specific language governing permissions and limitations
  under the License.
*****************************************************************************}

/// <summary>
///   Test data generator for unit tests of hash classes which have a rounds property
/// </summary>
program GenerateData;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  DECFormat,
  DECHash,
  DECUtil;

var
  Hash : THash_Snefru256;
  s    : RawByteString;
begin
  Hash := THash_Snefru256.Create;
  try
    try
      for var i := 2 to 8 do
      begin
        Hash.Rounds := i;

        s := '';
        WriteLn('  lDataRow := FTestData.AddRow;');
        WriteLn('  lDataRow.ExpectedOutput           := ''' + Hash.CalcString(s, TFormat_HEXL) + ''';');
        WriteLn('  lDataRow.ExpectedOutputUTFStrTest := ''' + Hash.CalcString(s, TFormat_HEXL) + ''';');
        WriteLn('  lDataRow.PaddingByte              := 1;');
        WriteLn('  lDataRow.Rounds                   := ' + i.ToString + ';');
        WriteLn('  lDataRow.AddInputVector('''');');
        WriteLn('');

        s := 'a';
        WriteLn('  lDataRow := FTestData.AddRow;');
        WriteLn('  lDataRow.ExpectedOutput           := ''' + Hash.CalcString(s, TFormat_HEXL) + ''';');

        WriteLn('  lDataRow.ExpectedOutputUTFStrTest := ''' + BytesToRawString(
                                                                TFormat_HEXL.Encode(
                      System.SysUtils.BytesOf(Hash.CalcString(string(RawByteString('a')))))) + ''';');
        WriteLn('  lDataRow.PaddingByte              := 1;');
        WriteLn('  lDataRow.Rounds                   := ' + i.ToString + ';');
        WriteLn('  lDataRow.AddInputVector(''a'');');
        WriteLn('');

      end;

      ReadLn;

    except
      on E: Exception do
        Writeln(E.ClassName, ': ', E.Message);
    end;
  finally
    Hash.Free;
  end;
end.
