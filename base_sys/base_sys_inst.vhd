	component base_sys is
		port (
			clk_clk          : in  std_logic                    := 'X'; -- clk
			pio_input_export : in  std_logic                    := 'X'; -- export
			pio_leds_export  : out std_logic_vector(7 downto 0);        -- export
			reset_reset_n    : in  std_logic                    := 'X'  -- reset_n
		);
	end component base_sys;

	u0 : component base_sys
		port map (
			clk_clk          => CONNECTED_TO_clk_clk,          --       clk.clk
			pio_input_export => CONNECTED_TO_pio_input_export, -- pio_input.export
			pio_leds_export  => CONNECTED_TO_pio_leds_export,  --  pio_leds.export
			reset_reset_n    => CONNECTED_TO_reset_reset_n     --     reset.reset_n
		);

