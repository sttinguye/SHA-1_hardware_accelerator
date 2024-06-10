
module base_sys (
	clk_clk,
	pio_input_export,
	pio_leds_export,
	reset_reset_n);	

	input		clk_clk;
	input		pio_input_export;
	output	[7:0]	pio_leds_export;
	input		reset_reset_n;
endmodule
