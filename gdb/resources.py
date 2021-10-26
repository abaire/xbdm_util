RESOURCES = {
    "target.xml": bytes(
        r"""<?xml version="1.0"?>
            <!DOCTYPE target SYSTEM "gdb-target.dtd">
            <target>
                <architecture>i386</architecture>
                <xi:include href="i386-xdbm.xml"/>
            </target>""",
        "utf-8",
    ),
    # Must be kept in sync with the ordering of registers in gdb_stub.py::_handle_read_general_registers
    "i386-xdbm.xml": bytes(
        r"""<?xml version="1.0"?>
        <!DOCTYPE target SYSTEM "gdb-target.dtd">
        <feature name="i386.xbdm">
          <flags id="i386_eflags" size="4">
            <field name="CF" start="0" end="0"/>
            <field name="" start="1" end="1"/>
            <field name="PF" start="2" end="2"/>
            <field name="" start="3" end="3"/>
            <field name="AF" start="4" end="4"/>
            <field name="" start="5" end="5"/>
            <field name="ZF" start="6" end="6"/>
            <field name="SF" start="7" end="7"/>
            <field name="TF" start="8" end="8"/>
            <field name="IF" start="9" end="9"/>
            <field name="DF" start="10" end="10"/>
            <field name="OF" start="11" end="11"/>
            <field name="IOPL" start="12" end="13"/>
            <field name="NT" start="14" end="14"/>
            <field name="" start="15" end="15"/>
            <field name="RF" start="16" end="16"/>
            <field name="VM" start="17" end="17"/>
            <field name="AC" start="18" end="18"/>
            <field name="VIF" start="19" end="19"/>
            <field name="VIP" start="20" end="20"/>
            <field name="ID" start="21" end="21"/>
            <field name="" start="22" end="31"/>
          </flags>

          <reg name="ebp" bitsize="32" type="data_ptr" regnum="0"/>
          <reg name="esp" bitsize="32" type="data_ptr"/>
          <reg name="eip" bitsize="32" type="code_ptr"/>
          <reg name="eflags" bitsize="32" type="i386_eflags"/>

          <reg name="eax" bitsize="32" type="int32" regnum="0"/>
          <reg name="ebx" bitsize="32" type="int32"/>
          <reg name="ecx" bitsize="32" type="int32"/>
          <reg name="edx" bitsize="32" type="int32"/>
          <reg name="esi" bitsize="32" type="int32"/>
          <reg name="edi" bitsize="32" type="int32"/>

        <!--
          <reg name="cs" bitsize="32" type="int32"/>
          <reg name="ss" bitsize="32" type="int32"/>
          <reg name="ds" bitsize="32" type="int32"/>
          <reg name="es" bitsize="32" type="int32"/>
          <reg name="fs" bitsize="32" type="int32"/>
          <reg name="gs" bitsize="32" type="int32"/>

          <!-- Segment descriptor caches and TLS base MSRs -->

          <!--reg name="cs_base" bitsize="32" type="int32"/>
          <reg name="ss_base" bitsize="32" type="int32"/>
          <reg name="ds_base" bitsize="32" type="int32"/>
          <reg name="es_base" bitsize="32" type="int32"/-->
          <reg name="fs_base" bitsize="32" type="int32"/>
          <reg name="gs_base" bitsize="32" type="int32"/>
          <reg name="k_gs_base" bitsize="32" type="int32"/>
        -->

          <flags id="i386_cr0" size="4">
            <field name="PG" start="31" end="31"/>
            <field name="CD" start="30" end="30"/>
            <field name="NW" start="29" end="29"/>
            <field name="AM" start="18" end="18"/>
            <field name="WP" start="16" end="16"/>
            <field name="NE" start="5" end="5"/>
            <field name="ET" start="4" end="4"/>
            <field name="TS" start="3" end="3"/>
            <field name="EM" start="2" end="2"/>
            <field name="MP" start="1" end="1"/>
            <field name="PE" start="0" end="0"/>
          </flags>

        <!--
          <flags id="i386_cr3" size="4">
            <field name="PDBR" start="12" end="31"/>
            <!--field name="" start="3" end="11"/>
            <field name="WT" start="2" end="2"/>
            <field name="CD" start="1" end="1"/>
            <field name="" start="0" end="0"/-->
            <field name="PCID" start="0" end="11"/>
          </flags>

          <flags id="i386_cr4" size="4">
            <field name="VME" start="0" end="0"/>
            <field name="PVI" start="1" end="1"/>
            <field name="TSD" start="2" end="2"/>
            <field name="DE" start="3" end="3"/>
            <field name="PSE" start="4" end="4"/>
            <field name="PAE" start="5" end="5"/>
            <field name="MCE" start="6" end="6"/>
            <field name="PGE" start="7" end="7"/>
            <field name="PCE" start="8" end="8"/>
            <field name="OSFXSR" start="9" end="9"/>
            <field name="OSXMMEXCPT" start="10" end="10"/>
            <field name="UMIP" start="11" end="11"/>
            <field name="LA57" start="12" end="12"/>
            <field name="VMXE" start="13" end="13"/>
            <field name="SMXE" start="14" end="14"/>
            <field name="FSGSBASE" start="16" end="16"/>
            <field name="PCIDE" start="17" end="17"/>
            <field name="OSXSAVE" start="18" end="18"/>
            <field name="SMEP" start="20" end="20"/>
            <field name="SMAP" start="21" end="21"/>
            <field name="PKE" start="22" end="22"/>
          </flags>

          <flags id="i386_efer" size="8">
            <field name="TCE" start="15" end="15"/>
            <field name="FFXSR" start="14" end="14"/>
            <field name="LMSLE" start="13" end="13"/>
            <field name="SVME" start="12" end="12"/>
            <field name="NXE" start="11" end="11"/>
            <field name="LMA" start="10" end="10"/>
            <field name="LME" start="8" end="8"/>
            <field name="SCE" start="0" end="0"/>
          </flags>
        -->

          <reg name="cr0" bitsize="32" type="i386_cr0"/>
        <!--
          <reg name="cr2" bitsize="32" type="int32"/>
          <reg name="cr3" bitsize="32" type="i386_cr3"/>
          <reg name="cr4" bitsize="32" type="i386_cr4"/>
          <reg name="cr8" bitsize="32" type="int32"/>
          <reg name="efer" bitsize="32" type="i386_efer"/>
        -->

          <reg name="st0" bitsize="80" type="i387_ext"/>
          <reg name="st1" bitsize="80" type="i387_ext"/>
          <reg name="st2" bitsize="80" type="i387_ext"/>
          <reg name="st3" bitsize="80" type="i387_ext"/>
          <reg name="st4" bitsize="80" type="i387_ext"/>
          <reg name="st5" bitsize="80" type="i387_ext"/>
          <reg name="st6" bitsize="80" type="i387_ext"/>
          <reg name="st7" bitsize="80" type="i387_ext"/>

        <!--
          <reg name="fctrl" bitsize="32" type="int" group="float"/>
          <reg name="fstat" bitsize="32" type="int" group="float"/>
          <reg name="ftag" bitsize="32" type="int" group="float"/>
          <reg name="fiseg" bitsize="32" type="int" group="float"/>
          <reg name="fioff" bitsize="32" type="int" group="float"/>
          <reg name="foseg" bitsize="32" type="int" group="float"/>
          <reg name="fooff" bitsize="32" type="int" group="float"/>
          <reg name="fop" bitsize="32" type="int" group="float"/>
         -->

        <!--
        </feature>
        <feature name="i386.xbdm.sse">

          <vector id="v4f" type="ieee_single" count="4"/>
          <vector id="v2d" type="ieee_double" count="2"/>
          <vector id="v16i8" type="int8" count="16"/>
          <vector id="v8i16" type="int16" count="8"/>
          <vector id="v4i32" type="int32" count="4"/>
          <vector id="v2i64" type="int64" count="2"/>

          <union id="vec128">
            <field name="v4_float" type="v4f"/>
            <field name="v2_double" type="v2d"/>
            <field name="v16_int8" type="v16i8"/>
            <field name="v8_int16" type="v8i16"/>
            <field name="v4_int32" type="v4i32"/>
            <field name="v2_int64" type="v2i64"/>
            <field name="uint128" type="uint128"/>
          </union>

          <flags id="i386_mxcsr" size="4">
            <field name="IE" start="0" end="0"/>
            <field name="DE" start="1" end="1"/>
            <field name="ZE" start="2" end="2"/>
            <field name="OE" start="3" end="3"/>
            <field name="UE" start="4" end="4"/>
            <field name="PE" start="5" end="5"/>
            <field name="DAZ" start="6" end="6"/>
            <field name="IM" start="7" end="7"/>
            <field name="DM" start="8" end="8"/>
            <field name="ZM" start="9" end="9"/>
            <field name="OM" start="10" end="10"/>
            <field name="UM" start="11" end="11"/>
            <field name="PM" start="12" end="12"/>
            <field name="FZ" start="15" end="15"/>
          </flags>

          <reg name="xmm0" bitsize="128" type="vec128"/>
          <reg name="xmm1" bitsize="128" type="vec128"/>
          <reg name="xmm2" bitsize="128" type="vec128"/>
          <reg name="xmm3" bitsize="128" type="vec128"/>
          <reg name="xmm4" bitsize="128" type="vec128"/>
          <reg name="xmm5" bitsize="128" type="vec128"/>
          <reg name="xmm6" bitsize="128" type="vec128"/>
          <reg name="xmm7" bitsize="128" type="vec128"/>

          <reg name="mxcsr" bitsize="32" type="i386_mxcsr" group="vector"/>

          -->
        </feature>
        """,
        "utf-8",
    ),
}
