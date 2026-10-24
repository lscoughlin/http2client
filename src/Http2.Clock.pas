/// Monotonic microsecond clock for request observability
// - this unit is part of the http2client project (see doc/design/
//   request-observability.md "Arrival stamping").
// - NowUs never steps backwards (no wall-clock adjustments): macOS reads
//   mach_absolute_time, other Unix systems clock_gettime(CLOCK_MONOTONIC).
unit Http2.Clock;

{$mode delphi}{$H+}

interface

type
  /// a replacement clock, see SetNowUsHook
  TNowUsFunc = function: Int64;

/// microseconds on a monotonic clock with an arbitrary origin; only
/// differences between two reads are meaningful
function NowUs: Int64;

/// make NowUs answer from AHook instead of the system clock, so a test can
/// script arrival stamps exactly.  The hook is called from any thread and
/// must be thread-safe.  Pass nil, or call ResetNowUsHook, to restore the
/// real clock.
procedure SetNowUsHook(const AHook: TNowUsFunc);

/// restore the system clock
procedure ResetNowUsHook;

implementation

uses
  SysUtils
  {$IFDEF DARWIN}
  {$ELSE}
  , BaseUnix, Unix
  {$ENDIF};

var
  GNowUsHook: TNowUsFunc = nil;

{$IFDEF DARWIN}
type
  TMachTimebaseInfo = record
    Numer, Denom: LongWord;
  end;

function mach_absolute_time: QWord; cdecl; external 'c' name 'mach_absolute_time';
function mach_timebase_info(var AInfo: TMachTimebaseInfo): LongInt; cdecl;
  external 'c' name 'mach_timebase_info';

var
  GTimebase: TMachTimebaseInfo;

function SystemNowUs: Int64;
begin
  // ticks * numer / denom is nanoseconds; Apple silicon runs 125/3
  Result := Int64((mach_absolute_time * GTimebase.Numer) div GTimebase.Denom
    div 1000);
end;

{$ELSE}
const
  cClockMonotonic = 1;   // CLOCK_MONOTONIC on Linux and the BSDs

// FPC's Unix and BaseUnix units do not export clock_gettime on every target
function SysClockGetTime(AClockId: LongInt; ATimeSpec: PTimeSpec): LongInt;
  cdecl; external 'c' name 'clock_gettime';

function SystemNowUs: Int64;
var
  TS: TTimeSpec;
begin
  if SysClockGetTime(cClockMonotonic, @TS) <> 0 then
    Exit(Int64(GetTickCount64) * 1000);
  Result := Int64(TS.tv_sec) * 1000000 + TS.tv_nsec div 1000;
end;
{$ENDIF}

function NowUs: Int64;
var
  Hook: TNowUsFunc;
begin
  Hook := GNowUsHook;
  if Assigned(Hook) then
    Result := Hook()
  else
    Result := SystemNowUs;
end;

procedure SetNowUsHook(const AHook: TNowUsFunc);
begin
  GNowUsHook := AHook;
end;

procedure ResetNowUsHook;
begin
  GNowUsHook := nil;
end;

{$IFDEF DARWIN}
initialization
  GTimebase.Numer := 1;
  GTimebase.Denom := 1;
  mach_timebase_info(GTimebase);
  if GTimebase.Denom = 0 then
    GTimebase.Denom := 1;
{$ENDIF}

end.
