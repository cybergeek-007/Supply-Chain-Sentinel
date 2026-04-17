rule SuspiciousEvalBuffer
{
    strings:
        $a = "eval(Buffer.from("
        $b = "new Function("
        $c = "child_process"
    condition:
        any of them
}
