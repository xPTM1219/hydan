#!/usr/bin/perl
# Quickhack script for making modifications to the opcode table


open(FILE, shift());
foreach (<FILE>){
	chomp;
	if ( /^(\/\*[^*]\*\/)\s*\{\s*([^}]+)\s*\}\s*(,?)\s*(.*)$/ ) {
		# this is an insn -- do something to it
		$cmt = $1;
		$line = $2;
		$comma = $3;

		#Table|MnemFlag|DestFlag|SrcFlag|AuxFlag|CPU|mnem|dest|src|aux|flags_effected|cmt
		($t,$mf,$df,$sf,$af,$cpu,$m,$d,$s,$a,$flg) = split ',', $line;

		# -------------------------------------------------
		# OK, add some custom code here to modify the insn
		# -------------------------------------------------

		print "$cmt { $t, $mf, $df, $sf, $af, $cpu, ";
		print "$m, $d, $s, $a, $flg }$comma\n";
	} else {
 		# this is some other line in the opcode.map file 
		print "$_\n";
	}
}
close(FILE);
