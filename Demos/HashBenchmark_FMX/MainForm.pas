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
unit MainForm;

interface

uses
  System.SysUtils, System.Types, System.UITypes, System.Classes, System.Variants,
  FMX.Types, FMX.Controls, FMX.Forms, FMX.Graphics, FMX.Dialogs,
  FMX.Controls.Presentation, FMX.StdCtrls, System.Rtti, FMX.Grid.Style,
  FMX.Grid, FMX.ScrollBox, FMX.Objects, System.Diagnostics;

type
  TFormMain = class(TForm)
    b_Start: TButton;
    sg_Results: TStringGrid;
    StringColumn1: TStringColumn;
    StringColumn2: TStringColumn;
    StringColumn3: TStringColumn;
    Rectangle1: TRectangle;
    TimerBenchmark: TTimer;
    procedure b_StartClick(Sender: TObject);
    procedure TimerBenchmarkTimer(Sender: TObject);
    procedure FormResize(Sender: TObject);
  private
    /// <summary>
    ///   Data which is being hashed for the benchmark
    /// </summary>
    FBenchmarkBuffer : TBytes;
    /// <summary>
    ///   Stopwatch used
    /// </summary>
    FStopwatch       : TStopwatch;
    /// <summary>
    ///   Currently processed gridrow
    /// </summary>
    FRowIndex        : Integer;

    /// <summary>
    ///   Runs the benchmark for a single class
    /// </summary>
    /// <param name="ClassName">
    ///   Name of the class to benchmark
    /// </param>
    /// <param name="RowIndex">
    ///   Number of the row where the results are to be displayed
    /// </param>
    procedure RunBenchmark(ClassName: string;
                           RowIndex: Integer);
  public
  end;

var
  FormMain: TFormMain;

implementation

uses
  Generics.Collections,
  DECBaseClass, DECHashBase, DECHash;

const
  /// <summary>
  ///   Number of times the buffer will be calculated a hash over
  /// </summary>
  cIterations = 10;

{$R *.fmx}

procedure TFormMain.b_StartClick(Sender: TObject);
var
  ClassNames : TStringList;
  ClassName  : string;
  i, n       : Integer;
begin
  sg_Results.RowCount := 0;
  // Create 1 MB Buffer
  SetLength(FBenchmarkBuffer, 1024*1024);

  n := 0;
  for i := 0 to Length(FBenchmarkBuffer)-1 do
  begin
    FBenchmarkBuffer[i] := n;
    inc(n);

    if (n > 255) then
      n := 0;
  end;

  ClassNames := TStringList.Create;

  try
    TDECHash.ClassList.GetClassList(ClassNames);
    ClassNames.Sort;

    for ClassName in ClassNames do
    begin
      sg_Results.RowCount := sg_Results.RowCount + 1;
      sg_Results.Cells[0, sg_Results.RowCount - 1] := ClassName;
    end;

    FRowIndex := 0;
    FStopwatch := TStopwatch.Create;
    TimerBenchmark.Enabled := true;
  finally
    ClassNames.Free;
  end;
end;

procedure TFormMain.FormResize(Sender: TObject);
var
  i : Integer;
  w : Single;
begin
  w := sg_Results.Width / sg_Results.ColumnCount;

  for i := 0 to sg_Results.ColumnCount - 1 do
    sg_Results.Columns[i].Width := w;
end;

procedure TFormMain.RunBenchmark(ClassName: string; RowIndex: Integer);
var
  Hash       : TDECHash;
  HashResult : TBytes;
  i          : Integer;
begin
  Hash := TDECHash.ClassByName(ClassName).Create;

  try
    FStopwatch.Reset;
    FStopwatch.Start;

    for i := 0 to cIterations - 1 do
    begin
      HashResult := Hash.CalcBytes(FBenchmarkBuffer);
    end;

    FStopwatch.Stop;

    sg_Results.Cells[1, RowIndex] :=
      Format('%0:f', [cIterations / (FStopwatch.ElapsedMilliseconds/1000)]);
    sg_Results.Cells[2, RowIndex] := FStopwatch.Elapsed.ToString;
  finally
    Hash.Free;
  end;
end;

procedure TFormMain.TimerBenchmarkTimer(Sender: TObject);
begin
  (Sender as TTimer).Enabled := false;

  RunBenchmark(sg_Results.Cells[0, FRowIndex], FRowIndex);
  Inc(FRowIndex);

  (Sender as TTimer).Enabled := true;
end;

end.
