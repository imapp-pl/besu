package org.hyperledger.besu.evmtool;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import org.apache.logging.log4j.Level;
import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.cli.config.NetworkName;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.ethereum.core.BlockHeader;
import org.hyperledger.besu.ethereum.core.BlockHeaderBuilder;
import org.hyperledger.besu.ethereum.core.Difficulty;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.mainnet.MainnetBlockHeaderFunctions;
import org.hyperledger.besu.ethereum.mainnet.ProtocolSpec;
import org.hyperledger.besu.ethereum.vm.BlockHashLookup;
import org.hyperledger.besu.evm.Code;
import org.hyperledger.besu.evm.EVM;
import org.hyperledger.besu.evm.frame.MessageFrame;
import org.hyperledger.besu.evm.log.LogsBloomFilter;
import org.hyperledger.besu.evm.precompile.PrecompileContractRegistry;
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

@Warmup(iterations = 10, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 100, time = 1, timeUnit = TimeUnit.SECONDS)
@Fork(1)
@State(Scope.Benchmark)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class ExecutionTimeBenchmark {

    @Param({""})
    private String code;

    private static final Logger LOG = LoggerFactory.getLogger(EvmToolCommand.class);
    private final Long gas = 10_000_000_000L;
    private final Wei gasPriceGWei = Wei.ZERO;
    private final Address sender = Address.fromHexString("0x00");
    private final Address receiver = Address.fromHexString("0x00");
    private final Bytes callData = Bytes.EMPTY;
    private final Wei ethValue = Wei.ZERO;
    private final File genesisFile = null;
    private final NetworkName network = null;

    private final EvmToolCommandOptionsModule daggerOptions = new EvmToolCommandOptionsModule();
    private final PrintStream out = System.out;

    private final Deque<MessageFrame> messageFrameStack = new ArrayDeque<>();
    private final OperationTracer tracer = OperationTracer.NO_TRACING;
    private ProtocolSpec protocolSpec;
    private MessageFrame messageFrame;
    private MessageCallProcessor mcp;

    @Setup
    public void prepare() {
        try {
            final EvmToolComponent component =
                DaggerEvmToolComponent.builder()
                    .dataStoreModule(new DataStoreModule())
                    .genesisFileModule(
                        network == null
                            ? genesisFile == null
                                ? GenesisFileModule.createGenesisModule(NetworkName.DEV)
                                : GenesisFileModule.createGenesisModule(genesisFile)
                            : GenesisFileModule.createGenesisModule(network))
                    .evmToolCommandOptionsModule(daggerOptions)
                    .metricsSystemModule(new MetricsSystemModule())
                    .build();

            final BlockHeader blockHeader =
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
            final PrecompileContractRegistry precompileContractRegistry =
                this.protocolSpec.getPrecompileContractRegistry();
            final EVM evm = this.protocolSpec.getEvm();
            Bytes codeHexString = Bytes.fromHexString(this.code);
            Code code = evm.getCode(Hash.hash(codeHexString), codeHexString);

            var updater = component.getWorldUpdater();
            updater.getOrCreate(sender);
            updater.getOrCreate(receiver);

            this.messageFrameStack.add(
                MessageFrame.builder()
                    .type(MessageFrame.Type.MESSAGE_CALL)
                    .messageFrameStack(this.messageFrameStack)
                    .worldUpdater(updater)
                    .initialGas(gas)
                    .contract(Address.ZERO)
                    .address(receiver)
                    .originator(sender)
                    .sender(sender)
                    .gasPrice(gasPriceGWei)
                    .inputData(callData)
                    .value(ethValue)
                    .apparentValue(ethValue)
                    .code(code)
                    .blockValues(blockHeader)
                    .depth(0)
                    .completer(c -> {})
                    .miningBeneficiary(blockHeader.getCoinbase())
                    .blockHashLookup(new BlockHashLookup(blockHeader, component.getBlockchain()))
                    .build());

            this.mcp = new MessageCallProcessor(evm, precompileContractRegistry);
        } catch (final IOException e) {
            LOG.error("Unable to create Genesis module", e);
        }
    }

    @TearDown
    public void tearDown() {
        final Transaction tx =
            new Transaction(
                0,
                Wei.ZERO,
                Long.MAX_VALUE,
                Optional.ofNullable(receiver),
                Wei.ZERO,
                null,
                callData,
                sender,
                Optional.empty());

        final long intrinsicGasCost =
            this.protocolSpec
                .getGasCalculator()
                .transactionIntrinsicGasCost(tx.getPayload(), tx.isContractCreation());
        final long accessListCost =
            tx.getAccessList()
                .map(list -> protocolSpec.getGasCalculator().accessListGasCost(list))
                .orElse(0L);
        final long evmGas = gas - this.messageFrame.getRemainingGas();
        out.println();
        out.println(
            new JsonObject()
                .put("gasUser", "0x" + Long.toHexString(evmGas))
                .put(
                    "gasTotal",
                    "0x" + Long.toHexString(evmGas + intrinsicGasCost) + accessListCost));
    }

    @Benchmark
    @OutputTimeUnit(TimeUnit.NANOSECONDS)
    public void benchmark(final Blackhole blackhole) {
        while (!this.messageFrameStack.isEmpty()) {
            this.messageFrame = this.messageFrameStack.peek();
            this.mcp.process(this.messageFrame, tracer);
                
            if (this.messageFrame.getExceptionalHaltReason().isPresent()) {
                out.println(this.messageFrame.getExceptionalHaltReason().get());
            }
            if (this.messageFrame.getRevertReason().isPresent()) {
                out.println(
                    new String(
                        this.messageFrame.getRevertReason().get().toArray(), StandardCharsets.UTF_8));
            }
        }
    }

    public static void main(final String[] args) throws RunnerException {
        
        Options opt = new OptionsBuilder()
                .include(ExecutionTimeBenchmark.class.getSimpleName())
                .build();

        new Runner(opt).run();

    }
}
