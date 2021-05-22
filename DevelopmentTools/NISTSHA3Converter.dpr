// Converts NIST SHA3 Testvector into DEC unit tests
program NISTSHA3Converter;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils, System.IOUtils, System.Types, System.Classes, DECUtil;

var
  Files: TStringDynArray;
  FileName: string;

/// <summary>
///   Reverse all the bits of all the bytes in a hex coded string
/// </summary>
function ReverseHexStringbits(InputString: string):string;
begin
  Result := '';

  while InputString.Length > 0 do
  begin
    Result := ReverseBits(UInt8(('0x' + Copy(InputString, 1 ,2)).ToInteger)).ToHexString + Result;
    Delete(InputString, 1, 2);
  end;
end;

procedure ConvertFile(const FileName: string);
var
  Contents    : TStringList;
  Output      : TStringList;
  Inputvector : TStringList;
  FinalBitLen : Integer;
  s1          : string;
begin
  Contents := TStringList.Create;
  Output   := TStringList.Create;
  InputVector := TStringList.Create;

  try
    Contents.LoadFromFile(FileName);

    for var s: string in Contents do
    begin
      // skip comments and empty lines
      if (not s.StartsWith('#')) and (not s.IsEmpty) then
      begin
        if s.StartsWith('Len') then
        begin
          Output.Add('  //Source https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-');
          Output.Add('  //       Validation-Program/documents/sha3/sha-3bittestvectors.zip,');
          Output.Add('  //       ' + FileName.TrimLeft(['.','\']) + ' ' + s);
          Output.Add('  lDataRow := FTestData.AddRow;');

          s1 := s.Remove(0, 6);
          FinalBitLen := s1.trim.ToInteger;
          FinalBitLen := FinalBitLen - ((FinalBitLen div 8) * 8);
        end;

        if s.StartsWith('Msg') then
        begin
          InputVector.Clear;
          s1 := s.Remove(0, 6);

          s1 := ReverseHexStringbits(s1);

          while s1.Length > 0 do
          begin
            InputVector.Add(Copy(s1, 1, 52));
            Delete(s1, 1, 52);
          end;

          s1 := InputVector[0];
          if (InputVector.Count > 0) then
            s1 := s1 + ''' +'
          else
            s1 := s1 + ');';

          Output.Add('  lDataRow.AddInputVector(''' + s1);
          InputVector.Delete(0);

          while InputVector.Count > 0 do
          begin
            s1 := InputVector[0];

            if (InputVector.Count > 1) then
              s1 := '''' +  s1 + ''' +'
            else
              s1 := '''' + s1 + ''');';

            Output.Add('                          ' + s1);
            InputVector.Delete(0);
          end;
        end;

        // Expected Output
        if s.StartsWith('MD') then
        begin
          InputVector.Clear;
          s1 := s.Remove(0, 6);

          s1 := ReverseHexStringbits(s1);

          while s1.Length > 0 do
          begin
            InputVector.Add(Copy(s1, 1, 40));
            Delete(s1, 1, 40);
          end;

          s1 := InputVector[0];
          if (InputVector.Count > 1) then
            s1 := s1 + ''' +'
          else
            s1 := s1 + '''' + ';';

          Output.Add('  lDataRow.ExpectedOutput :=           ''' + s1);
          InputVector.Delete(0);

          while InputVector.Count > 0 do
          begin
            s1 := InputVector[0];

            if (InputVector.Count > 1) then
              s1 := '''' + s1 + ''' +'
            else
              s1 := '   '  + '''' + s1 + '''' + ';';

            Output.Add('                          ' + s1);
            InputVector.Delete(0);
          end;

          { TODO : Unicode Ergebnis umsetzen }

          Output.Add('  lDataRow.FinalBitLength := ' + FinalBitLen.ToString + ';');
          Write('.');
        end;

//  lDataRow.ExpectedOutput           := '5e0c6a6c22222ef78a58e515bb7c5188b92f81f9' +
//                                       'aaea7bd3c335c109';
//  lDataRow.ExpectedOutputUTFStrTest := '098526f4e121e977c325078374bf13ee9b0f2ed3' +
//                                       '14ce743c5641cebe';
//  lDataRow.FinalBitLength := 0;
      end;
    end;

    // WriteLn(System.SysUtils.ExtractFileName(FileName).TrimEnd(['r','s','p']) + 'pas');
    Output.SaveToFile(System.SysUtils.ExtractFileName(FileName).TrimRight(['r','s','p']) + 'pas');
  finally
    Contents.Free;
    Output.Free;
    InputVector.Free;
  end;
end;

begin
  try
    Files := System.IOUtils.TDirectory.GetFiles('..\..\');
    for FileName in Files do
    begin
      if (System.SysUtils.ExtractFileExt(FileName) = '.rsp') then
      begin
        Write(FileName);
        ConvertFile(FileName);
        WriteLn;
      end;
    end;

    WriteLn('Press Enter');
    ReadLn;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
