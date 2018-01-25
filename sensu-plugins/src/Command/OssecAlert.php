<?php
namespace Ossec\SensuServer\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class OssecAlert extends Command {

	const STATUS_OK = 0;
	const STATUS_WARNING = 1;
	const STATUS_CRITICAL = 2;
	const STATUS_UNKNOWN = 3;

	const DEFAULT_WARNING = 1;
	const DEFAULT_CRITICAL = 2;
	const DEFAULT_MODE = '>=';
	const DEFAULT_TIME = '30 minutes';
	const DEFAULT_INDEX = 'logstash';
	const DEFAULT_AGGREGATE = 'count';

	protected function configure() {
		$this
			->setName('ossec-alert')
			->setDefinition([
				new InputArgument('apiUrl', InputArgument::REQUIRED, 'API Url for Elasticsearch'),
			])
			->addOption(
				'warning',
				'w',
				InputOption::VALUE_REQUIRED,
				'What value to expect to trigger a warning',
				static::DEFAULT_WARNING
			)
			->addOption(
				'critical',
				'c',
				InputOption::VALUE_REQUIRED,
				'What value to expect to trigger a critical',
				static::DEFAULT_CRITICAL
			)
			->addOption(
				'operator',
				'o',
				InputOption::VALUE_REQUIRED,
				'What comparison operator to use',
				static::DEFAULT_MODE
			)
			->addOption(
				'time',
				't',
				InputOption::VALUE_REQUIRED,
				'What time range to use',
				static::DEFAULT_TIME
			)
			->addOption(
				'index',
				'i',
				InputOption::VALUE_REQUIRED,
				'What index prefix to use',
				static::DEFAULT_INDEX
			)
			->addOption(
				'label',
				'l',
				InputOption::VALUE_REQUIRED,
				'What label to put on the output',
				'Result'
			)
			->addOption(
				'aggregate',
				'a',
				InputOption::VALUE_REQUIRED,
				'How to count up the query results for comparison',
				static::DEFAULT_AGGREGATE
			)
			->setDescription('Checks elasticsearch with a query and emits warnings and errors');
	}

	protected function execute(InputInterface $input, OutputInterface $output) {
		$file = __DIR__ . '/../../ossec-alert.json';
		$apiUrl = $input->getArgument('apiUrl');
		$warningLimit = $input->getOption('warning');
		$criticalLimit = $input->getOption('critical');
		$timeRange = $input->getOption('time');
		$operator = $input->getOption('operator');
		$indexPrefix = $input->getOption('index');
		$label = $input->getOption('label');

		if(!file_exists($file)) {
			echo sprintf('File does not exist: %s', $file);
			exit(STATUS_UNKNOWN);
		}

		$startTime = strtotime("-{$timeRange}");
		$endTime = time();

		$queryString = file_get_contents($file);
		$queryString = str_replace(["{{startTime}}", "{{endTime}}"], [$startTime . '000', $endTime . '000'], $queryString);

		$indexes = $this->getIndexes($indexPrefix, $startTime, $endTime);

		try {
			$data = $this->runQuery($apiUrl, $indexes, $queryString);
		} catch (\Exception $e) {
			echo sprintf('Exception: %s', $e->getMessage());
			exit(static::STATUS_UNKNOWN);
		}

		$result = $this->reduceData($data);
		$status = $this->compareResult($result, $operator, $warningLimit, $criticalLimit);

		$statusPrefix = $this->getStatusPrefix($status);

		echo sprintf('%s - %s: %s', $statusPrefix, $label, $result);
		exit($status);
	}

	/**
	 * @param string $indexPrefix
	 * @param int $startTime
	 * @param int $endTime
	 * @return string[]
	 */
	protected function getIndexes($indexPrefix, $startTime, $endTime) {
		$indexes = [];

		$startDate = strtotime(date('Y-m-d', $startTime));
		$endDate = strtotime(date('Y-m-d', $endTime));

		$tmpDate = $startDate;
		do {
			$indexes[] = $indexPrefix . '-' . date('Y.m.d', $tmpDate);
			$tmpDate += 86400;
		} while($tmpDate <= $endDate);

		return $indexes;
	}

	/**
	 * @param string $apiUrl
	 * @param array $indexes
	 * @param string $queryString
	 * @return array[]
	 * @throws \Exception
	 */
	protected function runQuery($apiUrl, array $indexes, $queryString) {
		$client = new \GuzzleHttp\Client();

		$apiUrl = ( substr($apiUrl, strlen($apiUrl) - 1) === '/' ? $apiUrl : $apiUrl . '/' )
			. implode(',', $indexes)
			. '/_search?pretty';

		$response = $client->post($apiUrl, [
			'body' => $queryString,
		]);

		$body = (string) $response->getBody();
		$data = json_decode($body, true);
		if(empty($data)) {
			throw new \Exception('No data from query');
		}

		return $data;
	}

    /**
     * @param array $data
     * @return float|int
     * @throws \Exception
     */
	protected function reduceData($data) {
		$aggregations = isset($data['aggregations']) ? $data['aggregations'] : null;
		if(empty($aggregations) || !is_array($aggregations)) {
			throw new \Exception('Invalid data: array aggregations does not exist');
		}

		$aggregation = reset($aggregations);
		$buckets = isset($aggregation['buckets']) ? $aggregation['buckets'] : null;
		if(!is_array($buckets)) {
			throw new \Exception('Invalid data: array buckets does not exist');
		}

		if(empty($buckets)) {
			return 0;
		}

        return $this->reduceBySum($buckets);
	}

	protected function reduceBySum($buckets) {
		return array_reduce($buckets, function($total, $bucket) {
			if(!is_array($bucket)) {
				return $total;
			}

			return $total + (isset($bucket['doc_count']) ? $bucket['doc_count'] : 0);
		});
	}

	/**
	 * @param int|float $result
	 * @param string $operatorString
	 * @param int|float $warningLimit
	 * @param int|float $criticalLimit
	 * @return int
	 */
	protected function compareResult($result, $operatorString, $warningLimit, $criticalLimit) {
		$operator = $this->getOperator($operatorString);
		if($operator($result, $criticalLimit)) {
			return static::STATUS_CRITICAL;
		}
		if($operator($result, $warningLimit)) {
			return static::STATUS_WARNING;
		}

		return static::STATUS_OK;
	}

	/**
	 * Converts an operator string to a closure that performs that operation
	 * @param string $operator_name
	 * @return callable
	 */
	protected function getOperator($operator_name) {
		$gt_eq = function($a, $b) {
			return $a >= $b;
		};
		$lt_eq = function($a, $b) {
			return $a <= $b;
		};
		$gt = function($a, $b) {
			return $a > $b;
		};
		$lt = function($a, $b) {
			return $a < $b;
		};

		switch($operator_name) {
			case ">=":
			case "gt_eq":
			case "gteq":
				return $gt_eq;
			case "<=":
			case "lt_eq":
			case "lteq":
				return $lt_eq;
			case ">":
			case "gt":
				return $gt;
			case "<":
			case "lt":
				return $lt;
		}

		return $gt_eq;
	}

	/**
	 * Converts a Status Code to a string to be placed in the text output
	 * @param int $status
	 * @return string
	 */
	protected function getStatusPrefix($status) {
		$prefix = 'UNKNOWN';
		if($status === static::STATUS_OK) {
			$prefix = 'OK';
		} elseif($status === static::STATUS_WARNING) {
			$prefix = 'WARNING';
		} elseif($status === static::STATUS_CRITICAL) {
			$prefix = 'CRITICAL';
		}
		return $prefix;
	}
}

