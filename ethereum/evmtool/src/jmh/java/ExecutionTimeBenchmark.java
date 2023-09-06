package org.hyperledger.besu.evmtool;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import org.apache.logging.log4j.Level;
import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.cli.config.EthNetworkConfig;
import org.hyperledger.besu.cli.config.NetworkName;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.ethereum.core.BlockHeader;
import org.hyperledger.besu.ethereum.core.BlockHeaderBuilder;
import org.hyperledger.besu.ethereum.core.Difficulty;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.debug.TraceOptions;
import org.hyperledger.besu.ethereum.mainnet.MainnetBlockHeaderFunctions;
import org.hyperledger.besu.ethereum.mainnet.ProtocolSpec;
import org.hyperledger.besu.ethereum.vm.BlockHashLookup;
import org.hyperledger.besu.evm.Code;
import org.hyperledger.besu.evm.EVM;
import org.hyperledger.besu.evm.frame.ExceptionalHaltReason;
import org.hyperledger.besu.evm.frame.MessageFrame;
import org.hyperledger.besu.evm.log.LogsBloomFilter;
import org.hyperledger.besu.evm.precompile.PrecompileContractRegistry;
import org.hyperledger.besu.evm.precompile.PrecompiledContract;
import org.hyperledger.besu.evm.processor.MessageCallProcessor;
import org.hyperledger.besu.evm.tracing.OperationTracer;
import org.hyperledger.besu.evmtool.DataStoreModule;
import org.hyperledger.besu.evmtool.EvmToolCommand;
import org.hyperledger.besu.evmtool.EvmToolCommandOptionsModule;
import org.hyperledger.besu.evmtool.EvmToolComponent;
import org.hyperledger.besu.evmtool.GenesisFileModule;
import org.hyperledger.besu.evmtool.MetricsSystemModule;
import org.hyperledger.besu.util.Log4j2ConfiguratorUtil;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.vertx.core.json.JsonObject;

import static java.nio.charset.StandardCharsets.UTF_8;

@Warmup(iterations = 2, time = 100, timeUnit = TimeUnit.MILLISECONDS)
@Measurement(iterations = 20, time = 100, timeUnit = TimeUnit.MILLISECONDS)
@Fork(value = 1) // , jvmArgs = {"-Xms1G", "-Xmx1G"}
@State(Scope.Benchmark)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class ExecutionTimeBenchmark {

    @Param({""})
    private String code;

    @Param({"1"})
    private int messagesPerRun;

    private Code codeParsed;
    private final Long gas = 10_000_000_000L;
    private final Wei gasPriceGWei = Wei.ZERO;
    private final Address sender = Address.fromHexString("0x00");
    private final Address receiver = Address.fromHexString("0x00");
    private final Bytes callData = Bytes.fromHexString("0x" + ("b".repeat(1<<17)));
    private final Wei ethValue = Wei.ZERO;

    private final EvmToolCommandOptionsModule daggerOptions = new EvmToolCommandOptionsModule();

    private final Deque<MessageFrame> messageFrameStack = new ArrayDeque<>();
    private final OperationTracer tracer = OperationTracer.NO_TRACING;
    private ProtocolSpec protocolSpec;
    private EvmToolComponent component;
    private BlockHeader blockHeader;

    private final String genesisConfig = "{\n" +
            "  \"config\": {\n" +
            "    \"chainId\": 1337,\n" +
            "    \"grayGlacierBlock\": 0,\n" +
            "    \"contractSizeLimit\": 2147483647,\n" +
            "    \"ethash\": {\n" +
            "      \"fixeddifficulty\": 100\n" +
            "    }\n" +
            "  },\n" +
            "  \"nonce\": \"0x42\",\n" +
            "  \"timestamp\": \"0x0\",\n" +
            "  \"extraData\": \"0x11bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82fa\",\n" +
            "  \"gasLimit\": \"0x1fffffffffffff\",\n" +
            "  \"difficulty\": \"0x10000\",\n" +
            "  \"mixHash\": \"0x0000000000000000000000000000000000000000000000000000000000000000\",\n" +
            "  \"coinbase\": \"0x0000000000000000000000000000000000000000\",\n" +
            "  \"alloc\": {\n" +
            "    \"fe3b557e8fb62b89f4916b721be55ceb828dbd73\": {\n" +
            "      \"privateKey\": \"8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63\",\n" +
            "      \"comment\": \"private key and this comment are ignored.  In a real chain, the private key should NOT be stored\",\n" +
            "      \"balance\": \"0xad78ebc5ac6200000\"\n" +
            "    },\n" +
            "    \"627306090abaB3A6e1400e9345bC60c78a8BEf57\": {\n" +
            "      \"privateKey\": \"c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3\",\n" +
            "      \"comment\": \"private key and this comment are ignored.  In a real chain, the private key should NOT be stored\",\n" +
            "      \"balance\": \"90000000000000000000000\"\n" +
            "    },\n" +
            "    \"f17f52151EbEF6C7334FAD080c5704D77216b732\": {\n" +
            "      \"privateKey\": \"ae6ae8e5ccbfb04590405997ee2d52d2b330726137b875053c36d94e974d162f\",\n" +
            "      \"comment\": \"private key and this comment are ignored.  In a real chain, the private key should NOT be stored\",\n" +
            "      \"balance\": \"90000000000000000000000\"\n" +
            "    }\n" +
            "  }\n" +
            "}\n";

    @Setup
    public void prepare() {

            component =
                DaggerEvmToolComponent.builder()
                    .dataStoreModule(new DataStoreModule())
                    .genesisFileModule(new MainnetGenesisFileModule(genesisConfig))
                    .evmToolCommandOptionsModule(daggerOptions)
                    .metricsSystemModule(new MetricsSystemModule())
                    .build();

            blockHeader =
                BlockHeaderBuilder.create()
                    .parentHash(Hash.EMPTY)
                    .coinbase(Address.ZERO)
                    .difficulty(Difficulty.ONE)
                    .number(1)
                    .gasLimit(5000)
                    .timestamp(Instant.now().toEpochMilli())
                    .ommersHash(Hash.EMPTY_LIST_HASH)
                    .stateRoot(Hash.EMPTY_TRIE_HASH)
                    .transactionsRoot(Hash.EMPTY)
                    .receiptsRoot(Hash.EMPTY)
                    .logsBloom(LogsBloomFilter.empty())
                    .gasUsed(0)
                    .extraData(Bytes.EMPTY)
                    .mixHash(Hash.EMPTY)
                    .nonce(0)
                    .blockHeaderFunctions(new MainnetBlockHeaderFunctions())
                    .buildBlockHeader();

            Log4j2ConfiguratorUtil.setLevel(
                "org.hyperledger.besu.ethereum.mainnet.ProtocolScheduleBuilder", Level.OFF);
            this.protocolSpec = component.getProtocolSpec().apply(0);
            Log4j2ConfiguratorUtil.setLevel(
                "org.hyperledger.besu.ethereum.mainnet.ProtocolScheduleBuilder", null);
            final EVM evm = this.protocolSpec.getEvm();

            Bytes codeHexString = Bytes.fromHexString(this.code);
            codeParsed = evm.getCode(Hash.hash(codeHexString), codeHexString);

            var updater = component.getWorldUpdater();
            updater.getOrCreate(sender);
            updater.getOrCreate(receiver);

    }

    @Setup(org.openjdk.jmh.annotations.Level.Iteration)
    public void prepareIteration() {
        for (int i = 0 ; i < messagesPerRun ; i ++ ) {
            final MessageFrame messageFrame =
                    MessageFrame.builder()
                            .type(MessageFrame.Type.MESSAGE_CALL)
                            .messageFrameStack(this.messageFrameStack)
                            .worldUpdater(component.getWorldUpdater())
                            .initialGas(gas)
                            .contract(Address.ZERO)
                            .address(receiver)
                            .originator(sender)
                            .sender(sender)
                            .gasPrice(gasPriceGWei)
                            .inputData(callData)
                            .value(ethValue)
                            .apparentValue(ethValue)
                            .code(codeParsed)
                            .blockValues(blockHeader)
                            .depth(0)
                            .completer(c -> {})
                            .miningBeneficiary(Address.ZERO)
                            .blockHashLookup(new BlockHashLookup(blockHeader, component.getBlockchain()))
                            .build();
            this.messageFrameStack.add(messageFrame);
        }
    }

    @Benchmark
    @OutputTimeUnit(TimeUnit.NANOSECONDS)
    public void benchmark(final Blackhole blackhole) {
        final EVM evm = this.protocolSpec.getEvm();
        System.out.println(evm.operationAtOffset(codeParsed, 120));
        while (true) {
            final MessageFrame messageFrame = this.messageFrameStack.peek();
            if (messageFrame == null) {
                return;
            }
            final PrecompiledContract precompile = protocolSpec.getPrecompileContractRegistry().get(messageFrame.getContractAddress());
            if (precompile != null) {
                executePrecompile(precompile, messageFrame, tracer);
            } else {
                if (messageFrame.getState() == MessageFrame.State.NOT_STARTED) {
                    messageFrame.setState(MessageFrame.State.CODE_EXECUTING);
                }
                evm.runToHalt(messageFrame, tracer);
                if (messageFrame.getState() == MessageFrame.State.CODE_SUCCESS) {
                    messageFrame.setState(MessageFrame.State.COMPLETED_SUCCESS);
                }
            }
            if (messageFrame.getState() == MessageFrame.State.COMPLETED_SUCCESS) {
//                messageFrame.getWorldUpdater().commit();
                messageFrame.notifyCompletion();
                this.messageFrameStack.remove();
            } else if (messageFrame.getState() != MessageFrame.State.CODE_SUSPENDED) {
                throw new RuntimeException("code failed " + messageFrame.getState() + " " + messageFrame.getPC());
            }
        }
    }

    private void executePrecompile(
            final PrecompiledContract contract,
            final MessageFrame frame,
            final OperationTracer operationTracer) {
        final long gasRequirement = contract.gasRequirement(frame.getInputData());
        if (frame.getRemainingGas() < gasRequirement) {
            frame.setExceptionalHaltReason(Optional.of(ExceptionalHaltReason.INSUFFICIENT_GAS));
            frame.setState(MessageFrame.State.EXCEPTIONAL_HALT);
        } else {
            frame.decrementRemainingGas(gasRequirement);
            final PrecompiledContract.PrecompileContractResult result =
                    contract.computePrecompile(frame.getInputData(), frame);
            operationTracer.tracePrecompileCall(frame, gasRequirement, result.getOutput());
            if (result.isRefundGas()) {
                frame.incrementRemainingGas(gasRequirement);
            }
            if (frame.getState() == MessageFrame.State.REVERT) {
                frame.setRevertReason(result.getOutput());
            } else {
                frame.setOutputData(result.getOutput());
            }
            frame.setState(result.getState());
            frame.setExceptionalHaltReason(result.getHaltReason());
        }
    }

    public static void main(final String[] args) throws RunnerException {
        
        Options opt = new OptionsBuilder()
                .include(ExecutionTimeBenchmark.class.getSimpleName())
                .build();

        new Runner(opt).run();

    }
}
