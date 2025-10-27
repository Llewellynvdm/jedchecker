<?php
/**
 * @package    Joomla.JEDChecker
 *
 * @copyright  Copyright (C) 2025 Open Source Matters, Inc. All rights reserved.
 *
 * @license    GNU General Public License version 2 or later; see LICENSE.txt
 */

defined('_JEXEC') or die('Restricted access');

use Joomla\Filesystem\Folder;
use Joomla\CMS\Language\Text;

// Include the rule base class
require_once JPATH_COMPONENT_ADMINISTRATOR . '/models/rule.php';

// Include the helper class
require_once JPATH_COMPONENT_ADMINISTRATOR . '/libraries/helper.php';

/**
 * JedcheckerRulesSecurity
 *
 * @since  1.0
 * Checks for security issues: obfuscated loaders, executable files, badly named files
 */
class JedcheckerRulesSecurity extends JEDcheckerRule
{
	/**
	 * The formal ID of this rule.
	 *
	 * @var    string
	 */
	protected $id = 'Security';

	/**
	 * The title or caption of this rule.
	 *
	 * @var    string
	 */
	protected $title = 'COM_JEDCHECKER_RULE_SECURITY';

	/**
	 * The description of this rule.
	 *
	 * @var    string
	 */
	protected $description = 'COM_JEDCHECKER_RULE_SECURITY_DESC';

	/**
	 * The ordering value to sort rules in the menu.
	 *
	 * @var    integer
	 */
	public static $ordering = 750;

	/**
	 * Regex pattern for obfuscated code detection
	 *
	 * @var    string
	 */
	protected $obfuscatedRegex = '';

	/**
	 * Executable file extensions that should not be in Joomla extensions
	 *
	 * @var    string[]
	 */
	protected $executableExts = array();

	/**
	 * Shell script extensions
	 *
	 * @var    string[]
	 */
	protected $shellExts = array();

	/**
	 * Characters that should not appear in filenames
	 *
	 * @var string
	 */
	protected $badChars = '';

	/**
	 * Initiates the file search and check
	 *
	 * @return    void
	 */
	public function check()
	{
		$executableExts = explode(',', $this->params->get('executable_extensions', ''));
		$this->executableExts = array_map('trim', $executableExts);

		$shellExts = explode(',', $this->params->get('shell_extensions', ''));
		$this->shellExts = array_map('trim', $shellExts);

		$this->badChars = $this->params->get('bad_filename_chars', '');

		// Build obfuscated patterns regex
		$this->buildObfuscatedRegex();

		// Get all files recursively
		$files = Folder::files($this->basedir, '.', true, true);

		foreach ($files as $file)
		{
			// Check for bad filenames
			$this->checkBadFilename($file);

			// Check for executable files
			$this->checkExecutableFile($file);

			// Check for obfuscated code in PHP files
			if (preg_match('/\.php$/i', $file))
			{
				$this->checkObfuscatedCode($file);
			}
		}
	}

	/**
	 * Build regex pattern for obfuscated code detection
	 *
	 * @return void
	 */
	protected function buildObfuscatedRegex()
	{
		$patterns = explode(',', $this->params->get('obfuscated_patterns', ''));
		$regexParts = array();

		foreach ($patterns as $pattern)
		{
			$pattern = trim($pattern);

			if (empty($pattern))
			{
				continue;
			}

			$regexParts[] = $this->generateRegex($pattern);
		}

		if (!empty($regexParts))
		{
			$this->obfuscatedRegex = '/(?:' . implode('|', $regexParts) . ')/';
		}
	}

	/**
	 * Generates regular expression for a given pattern with word boundaries
	 *
	 * @param   string  $pattern  The string to match
	 *
	 * @return string
	 */
	protected function generateRegex($pattern)
	{
		$regex = preg_quote($pattern, '/');

		// Add word boundary check for patterns starting/ending with word characters (\w = [a-zA-Z0-9_])
		if (preg_match('/\w/', $pattern[0]))
		{
			$regex = '\b' . $regex;
		}

		if (preg_match('/\w/', $pattern[strlen($pattern) - 1]))
		{
			$regex .= '\b';
		}

		return $regex;
	}

	/**
	 * Check if file contains obfuscated code patterns
	 *
	 * @param   string  $file  The file path
	 *
	 * @return void
	 */
	protected function checkObfuscatedCode($file)
	{
		if (empty($this->obfuscatedRegex))
		{
			return;
		}

		$content = file_get_contents($file);

		if (empty($content))
		{
			return;
		}

		// Check for obfuscated patterns
		if (preg_match($this->obfuscatedRegex, $content, $matches))
		{
			$this->report->addError(
				$file,
				Text::sprintf('COM_JEDCHECKER_ERROR_SECURITY_OBFUSCATED_CODE', $matches[0])
			);
		}
	}

	/**
	 * Check if file is an executable or shell script
	 *
	 * @param   string  $file  The file path
	 *
	 * @return void
	 */
	protected function checkExecutableFile($file)
	{
		$extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));

		// Check executable extensions
		if (in_array($extension, $this->executableExts))
		{
			$this->report->addWarning(
				$file,
				Text::_('COM_JEDCHECKER_ERROR_SECURITY_EXECUTABLE_FILE')
			);
			return;
		}

		// Check shell script extensions
		if (in_array($extension, $this->shellExts))
		{
			$this->report->addWarning(
				$file,
				Text::_('COM_JEDCHECKER_ERROR_SECURITY_SHELL_SCRIPT')
			);
			return;
		}

		// Check for shebang in files without extension or with any extension
		$this->checkShebang($file);
	}

	/**
	 * Check if file starts with shebang (#!)
	 *
	 * @param   string  $file  The file path
	 *
	 * @return void
	 */
	protected function checkShebang($file)
	{
		$handle = @fopen($file, 'r');

		if ($handle === false)
		{
			return;
		}

		$firstBytes = fread($handle, 2);
		fclose($handle);

		if ($firstBytes === '#!')
		{
			$this->report->addWarning(
				$file,
				Text::_('COM_JEDCHECKER_ERROR_SECURITY_SHEBANG_FILE')
			);
		}
	}

	/**
	 * Check if filename contains bad characters
	 *
	 * @param   string  $file  The file path
	 *
	 * @return void
	 */
	protected function checkBadFilename($file)
	{
		if (empty($this->badChars))
		{
			return;
		}

		$filename = basename($file);
		$chars = strpbrk($filename, $this->badChars);
		if ($chars !== false)
		{
			$char = $chars[0];
			$displayChar = ($char === ' ') ? 'space' : $char;
			$this->report->addNotice(
				$file,
				Text::sprintf('COM_JEDCHECKER_ERROR_SECURITY_BAD_FILENAME_CHAR', $displayChar)
			);
		}
	}
}
