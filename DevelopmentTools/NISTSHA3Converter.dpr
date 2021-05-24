// Converts NIST SHA3 Testvector into DEC unit tests
program NISTSHA3Converter;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils, System.IOUtils, System.Types, System.Classes, DECUtil,
  DECHashBase, DECHash, DECFormat, DECHashBitBase;

var
  Files: TStringDynArray;
  FileName: string;

/// <summary>
///   Split a too loong string into multiple lines
/// </summary>
/// <param name="Line">
///   Input string which shall be split
/// </param>
/// <param name="WrapAt">
///   Number of characters after which to wrap
/// </param>
/// <param name="WrapList">
///   Assigned list where the wrapped lines shall be stored in. The list will
///   initially get cleared.
/// </param>
procedure WrapLine(Line: string; WrapAt: Integer; WrapList: TStringList);
begin
  Assert(Assigned(WrapList), 'Unassigned list given');

  WrapList.Clear;

  while Line.Length > 0 do
  begin
    WrapList.Add(Copy(Line, 1, WrapAt));
    Delete(Line, 1, WrapAt);
  end;
end;

procedure ConvertFile(const FileName: string);
var
  Contents     : TStringList;
  Output       : TStringList;
  Inputvector  : TStringList;
  FinalByteLen : Integer;
  s1           : string;
  UTFHash      : string;
  HashClass    : TDECHash;
begin
  HashClass := TDECHash.ClassByName('THash_' + FileName.Remove(14).Remove(0, 6)).Create;

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
          FinalByteLen := s1.trim.ToInteger; 
          FinalByteLen := s1.trim.ToInteger mod 8;
        end;

        if s.StartsWith('Msg') then
        begin
          s1 := s.Remove(0, 6);

          TDECHashBit(HashClass).FinalByteLength := FinalByteLen;
          UTFHash := BytesToRawString(TFormat_HEXL.Encode(
                       System.SysUtils.BytesOf(HashClass.CalcString(TFormat_HexL.Decode(s1)))));
          
          WrapLine(S1, 52, InputVector);

          s1 := InputVector[0];
          if (InputVector.Count > 1) then
            s1 := s1 + ''' +'
          else
            s1 := s1 + '''));';

          Output.Add('  lDataRow.AddInputVector(TFormat_HexL.Decode(''' + s1);
          InputVector.Delete(0);

          while InputVector.Count > 0 do
          begin
            s1 := InputVector[0];

            if (InputVector.Count > 1) then
              s1 := '''' +  s1 + ''' +'
            else
              s1 := '''' + s1 + '''));';

            Output.Add('                          ' + s1);
            InputVector.Delete(0);
          end;
        end;

        // Expected Output
        if s.StartsWith('MD') then
        begin
          s1 := s.Remove(0, 5);

          // Normal hash
          WrapLine(s1, 40, InputVector);

          s1 := InputVector[0];
          if (InputVector.Count > 1) then
            s1 := s1 + ''' +'
          else
            s1 := s1 + '''' + ';';

          Output.Add('  lDataRow.ExpectedOutput           := ''' + s1);
          InputVector.Delete(0);

          while InputVector.Count > 0 do
          begin
            s1 := InputVector[0];

            if (InputVector.Count > 1) then
              s1 := '''' + s1 + ''' +'
            else
              s1 := '   '  + '''' + s1 + '''' + ';';

            Output.Add('                                    ' + s1);
            InputVector.Delete(0);
          end;

          // UnicodeString hash
          s1 := UTFHash;
          WrapLine(s1, 40, InputVector);

          s1 := InputVector[0];
          if (InputVector.Count > 1) then
            s1 := s1 + ''' +'
          else
            s1 := s1 + '''' + ';';

          Output.Add('  lDataRow.ExpectedOutputUTFStrTest := ''' + s1);
          InputVector.Delete(0);

          while InputVector.Count > 0 do
          begin
            s1 := InputVector[0];

            if (InputVector.Count > 1) then
              s1 := '''' + s1 + ''' +'
            else
              s1 := '   '  + '''' + s1 + '''' + ';';

            Output.Add('                                    ' + s1);
            InputVector.Delete(0);
          end;


          Output.Add('  lDataRow.FinalBitLength := ' + FinalByteLen.ToString + ';');
          Write('.');
        end;

//      CheckEquals(FTestData[i].ExpectedOutputUTFStrTest,
//                  BytesToRawString(
//                    TFormat_HEXL.Encode(
//                      System.SysUtils.BytesOf(HashClass.CalcString(InpStr)))),
//                  'Index: ' + IntToStr(i) + ' - expected: <' +
//                  string(FTestData[i].ExpectedOutputUTFStrTest) + '> but was: <' +
//                  string(BytesToRawString(
//                    TFormat_HEXL.Encode(
//                      System.SysUtils.BytesOf(HashClass.CalcString(InpStr))))) + '>');


      end;
    end;

    // WriteLn(System.SysUtils.ExtractFileName(FileName).TrimEnd(['r','s','p']) + 'pas');
    Output.SaveToFile(System.SysUtils.ExtractFileName(FileName).TrimRight(['r','s','p']) + 'pas');
  finally
    Contents.Free;
    Output.Free;
    InputVector.Free;
    HashClass.Free;
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
